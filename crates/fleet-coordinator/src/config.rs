//! Coordinator configuration.
//!
//! This is the in-process configuration struct plus light validation. Loading
//! it from a file (TOML) and wiring the CLI is the job of `fleet-bin`; here we
//! only model the shape so the rest of the crate can depend on it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fleet_core::policy::Policy;

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

/// Which kind of login provider a `[[auth.providers]]` entry configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// `GitHub` (`OAuth2`; identity from `/user` + `/user/emails`).
    Github,
    /// Any `OpenID` Connect issuer (discovery + verified `id_token`).
    Oidc,
    /// Codeberg / any Forgejo instance (OIDC; `issuer` defaults to Codeberg).
    Codeberg,
    /// GitLab (OIDC; `issuer` defaults to gitlab.com).
    Gitlab,
}

impl ProviderKind {
    /// Parse the config label (`github` | `oidc` | `codeberg` | `gitlab`).
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "github" => Some(Self::Github),
            "oidc" => Some(Self::Oidc),
            "codeberg" => Some(Self::Codeberg),
            "gitlab" => Some(Self::Gitlab),
            _ => None,
        }
    }
}

/// One configured login provider (`[[auth.providers]]`).
///
/// A provider **proves who you are; it does not name you**: login yields
/// `(provider, immutable subject id, verified email)` and the username is
/// chosen in fleet on first login (forgs' signup). `name` is the configured
/// instance name and appears in URLs (`/auth/{name}/start`), so two instances
/// of the same software are two providers whose subjects never mix.
#[derive(Clone)]
pub struct ProviderConfig {
    /// Which adapter.
    pub kind: ProviderKind,
    /// Instance name (`github`, `codeberg`, `gitlab-work`): `[a-z0-9_-]`.
    pub name: String,
    /// OAuth client id. Public.
    pub client_id: String,
    /// OAuth client secret (`fleet-bin` resolves `client_secret_path`).
    /// Required by every adapter: GitHub ignores PKCE, so the secret is what
    /// makes an intercepted code unspendable.
    pub client_secret: String,
    /// The OIDC issuer. Required for `oidc`; overrides the preset for
    /// `codeberg` / `gitlab`; for `github`, a GitHub Enterprise Server origin.
    pub issuer: Option<String>,
    /// GitHub only: explicit endpoints, for a loopback test stub. All three
    /// or none.
    pub github_endpoints: Option<GithubEndpoints>,
}

/// GitHub's three URLs, overridable as a unit (tests, GHES).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubEndpoints {
    /// Browser-facing authorize endpoint.
    pub authorize_url: String,
    /// Code → access token.
    pub access_token_url: String,
    /// REST API base (`/user`, `/user/emails`).
    pub api_base: String,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("issuer", &self.issuer)
            .field("github_endpoints", &self.github_endpoints)
            .finish()
    }
}

/// The `[auth]` table.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Login providers, offered on `/auth/login` and `/auth/providers`.
    ///
    /// Empty is a supported deployment (air-gapped / development): users are
    /// then created with `coordinator user-token`, and CLI device login has
    /// no way to complete.
    pub providers: Vec<ProviderConfig>,
}

/// The GitHub Actions OIDC issuer the coordinator accepts workload tokens
/// from (architecture §6.7).
///
/// Signed JWTs, a JWKS endpoint, and claims to verify. Independent of the
/// login providers — a fleet may have CI without user login, or the reverse.
#[derive(Debug, Clone)]
pub struct GithubActionsConfig {
    /// The expected `iss` claim.
    pub issuer: String,
    /// Where the issuer publishes its signing keys.
    ///
    /// Overridable (rather than derived from `issuer`) so the integration
    /// tests can point it at a loopback stub — the only way to exercise
    /// signature verification without github.com.
    pub jwks_url: String,
    /// The `aud` claim a workload token must carry.
    ///
    /// **Required, and deliberately without a default.** GitHub's default
    /// audience is `https://github.com/<owner>`, which is not specific to any
    /// service: a token minted for some *other* system that also took the
    /// default would then be replayable against this fleet. Set it to the
    /// coordinator's `public_url` and have the workflow request that audience
    /// explicitly.
    pub audience: String,
    /// How long (seconds) a cached JWKS is served before a refetch.
    pub jwks_refresh_secs: u64,
    /// Floor (seconds) between refetches forced by an unknown `kid`.
    ///
    /// An unknown `kid` is how a key rotation looks, so it must trigger a
    /// refetch; but the `kid` is attacker-chosen, so an unbounded one turns
    /// `POST /auth/token` into a fetch amplifier aimed at the issuer.
    pub jwks_min_refetch_secs: u64,
    /// How long (seconds) a minted workload token is valid.
    ///
    /// Per job, by intent. A job that outlives it must re-run `ci login`:
    /// there is no refresh path for a workload token (`Refresh` is
    /// session-only), and that bound is documented in
    /// `docs/ci-github-actions.md` rather than left to be discovered as a
    /// flake.
    pub workload_token_ttl_secs: u64,
}

impl Default for GithubActionsConfig {
    fn default() -> Self {
        Self {
            issuer: DEFAULT_GHA_ISSUER.to_owned(),
            jwks_url: DEFAULT_GHA_JWKS_URL.to_owned(),
            // No sensible default exists; `validate()` refuses an empty one.
            audience: String::new(),
            jwks_refresh_secs: 3600,
            jwks_min_refetch_secs: 60,
            workload_token_ttl_secs: 3600,
        }
    }
}

/// GitHub's Actions OIDC issuer.
pub const DEFAULT_GHA_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// GitHub's Actions OIDC JWKS endpoint.
pub const DEFAULT_GHA_JWKS_URL: &str =
    "https://token.actions.githubusercontent.com/.well-known/jwks";
/// Ceiling on [`GithubActionsConfig::workload_token_ttl_secs`].
///
/// A workload token is a pure bearer credential handed to a CI runner; twelve
/// hours is already generous for "one job".
const MAX_WORKLOAD_TOKEN_TTL_SECS: u64 = 12 * 60 * 60;

/// The default `default_org` name.
pub const DEFAULT_ORG_NAME: &str = "default";

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
    /// `login --fleet-url` / `node up --fleet-url`.
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
    /// How long (seconds) a freshly minted **refresh token** is valid.
    ///
    /// Default 30 days, deliberately the same figure as
    /// the API-key TTL cap, which is already this tree's
    /// stated ceiling for "a durable bearer credential a member may hold". A
    /// refresh token is strictly weaker than an auth key — it mints only
    /// sessions, for one user, in one org, and enrolls nothing — so it does not
    /// deserve a longer bound.
    ///
    /// There is deliberately **no cap** on this value, matching
    /// `session_ttl_secs`: a second capped-vs-uncapped rule with no enforcement
    /// story would be worse than neither. What bounds a leak in practice is
    /// revocation (`probe-rs-fleet logout --all`), which is why that verb
    /// exists.
    pub refresh_token_ttl_secs: u64,
    /// How old (seconds) a node token may get before it is rotated.
    pub node_token_rotate_secs: u64,
    /// How long (seconds) an approval-pending node registration lives
    /// (architecture §4.2 rung 3).
    ///
    /// Short on purpose: the `user_code` is ~40 bits and guessable by
    /// construction, so the TTL is half of what bounds enumeration (the other
    /// half being that every attempt is audited).
    pub pending_node_ttl_secs: u64,
    /// Ceiling on live (unconsumed, unexpired) pending node registrations.
    ///
    /// `/node/register/start` is unauthenticated and *writes a row*, unlike the
    /// stateless device flow, so without a cap an unauthenticated caller can
    /// grow the table freely within each TTL window. At the ceiling the route
    /// answers `503 too_many_pending`: refusing a new enrollment is
    /// recoverable, unbounded growth in a table an unauthenticated caller
    /// controls is not.
    pub max_pending_nodes: i64,
    /// The **name** of the deployment's shared org, created at startup if
    /// absent. The org the interim admin verbs default to when the operator
    /// names none. Not consulted for any authenticated request: a user acts
    /// in an org they name (default: their personal org), a node in its own
    /// node's org.
    pub default_org: String,
    /// Login providers (`[[auth.providers]]`).
    pub auth: AuthConfig,
    /// The dedicated cookie/CSRF secret (≥ 32 bytes), loaded by `fleet-bin`
    /// from `csrf_secret_path`. **Not** derived from the signing key.
    ///
    /// `None` is refused by [`crate::build`]; a coordinator constructed
    /// directly (tests) then gets a random per-process secret, so browser
    /// sessions do not survive a restart.
    pub csrf_secret: Option<Vec<u8>>,
    /// The GitHub Actions OIDC issuer backing `probe-rs-fleet ci login`
    /// (architecture §6.7).
    ///
    /// `None` is a supported deployment: a fleet with no CI. The exchange then
    /// answers a named `503` (`workload_oidc_unconfigured`), mirroring
    /// `device_flow_unconfigured`, so the CLI can say *why*.
    pub github_actions: Option<GithubActionsConfig>,
}

impl CoordinatorConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::Config`] if a required path or value is
    /// empty/zero, or a `[tls]` table is missing one of its two paths.
    // One `if` per rule, and each rule's comment is the reason it exists;
    // splitting them across helpers would separate each check from its
    // justification, which is the part worth reading.
    #[allow(clippy::too_many_lines)]
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
            ("refresh_token_ttl_secs", self.refresh_token_ttl_secs),
            ("node_token_rotate_secs", self.node_token_rotate_secs),
            ("pending_node_ttl_secs", self.pending_node_ttl_secs),
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
        if self.max_pending_nodes <= 0 {
            return Err(CoordinatorError::Config(
                "max_pending_nodes must be positive, or interactive node approval \
                 can never succeed"
                    .to_owned(),
            ));
        }
        // Through forgs' own naming rules and reserved list — the same check
        // every org-creation path applies, so a name only one path accepts
        // cannot exist.
        if let Err(e) = crate::state::fleet_schema().canonical_name(
            crate::subject::ORG_KIND,
            &self.default_org,
            forgs::schema::NameOrigin::App,
        ) {
            return Err(CoordinatorError::Config(format!(
                "default_org `{}` is not a usable org name: {e}",
                self.default_org
            )));
        }
        if let Some(secret) = &self.csrf_secret {
            if secret.len() < 32 {
                return Err(CoordinatorError::Config(
                    "the CSRF secret must be at least 32 bytes".to_owned(),
                ));
            }
        }
        let mut names: Vec<&str> = Vec::new();
        for p in &self.auth.providers {
            if names.contains(&p.name.as_str()) {
                return Err(CoordinatorError::Config(format!(
                    "auth.providers: duplicate provider name `{}`",
                    p.name
                )));
            }
            names.push(&p.name);
            for (label, value) in [
                ("name", &p.name),
                ("client_id", &p.client_id),
                ("client_secret", &p.client_secret),
            ] {
                if value.trim().is_empty() {
                    return Err(CoordinatorError::Config(format!(
                        "auth.providers `{}`: {label} must be non-empty",
                        p.name
                    )));
                }
            }
            if p.kind == ProviderKind::Oidc
                && p.issuer.as_deref().is_none_or(|i| i.trim().is_empty())
            {
                return Err(CoordinatorError::Config(format!(
                    "auth.providers `{}`: an `oidc` provider needs an issuer",
                    p.name
                )));
            }
        }
        if let Some(gha) = &self.github_actions {
            for (label, value) in [
                ("github_actions.issuer", &gha.issuer),
                ("github_actions.jwks_url", &gha.jwks_url),
                // The one with real teeth: an empty audience would mean
                // accepting GitHub's fleet-unspecific default, and with it any
                // token minted for another service under the same owner.
                ("github_actions.audience", &gha.audience),
            ] {
                if value.trim().is_empty() {
                    return Err(CoordinatorError::Config(format!(
                        "{label} must be non-empty when a [github_actions] table is present"
                    )));
                }
            }
            for (label, value) in [
                ("github_actions.jwks_refresh_secs", gha.jwks_refresh_secs),
                (
                    "github_actions.workload_token_ttl_secs",
                    gha.workload_token_ttl_secs,
                ),
            ] {
                if value == 0 {
                    return Err(CoordinatorError::Config(format!(
                        "{label} must be non-zero"
                    )));
                }
            }
            if gha.workload_token_ttl_secs > MAX_WORKLOAD_TOKEN_TTL_SECS {
                return Err(CoordinatorError::Config(format!(
                    "github_actions.workload_token_ttl_secs must not exceed \
                     {MAX_WORKLOAD_TOKEN_TTL_SECS} (a workload token is per job)"
                )));
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
    pub fn rotation_policy(&self) -> forgs::RotationPolicy {
        forgs::RotationPolicy {
            max_age_secs: self.node_token_rotate_secs,
            ..forgs::RotationPolicy::DEFAULT
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
            refresh_token_ttl_secs: 30 * 24 * 3600,
            node_token_rotate_secs: forgs::RotationPolicy::DEFAULT.max_age_secs,
            pending_node_ttl_secs: 15 * 60,
            max_pending_nodes: 256,
            default_org: DEFAULT_ORG_NAME.to_owned(),
            auth: AuthConfig::default(),
            csrf_secret: None,
            github_actions: None,
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
            |c| c.refresh_token_ttl_secs = 0,
            |c| c.node_token_rotate_secs = 0,
            |c| c.pending_node_ttl_secs = 0,
            |c| c.max_pending_nodes = 0,
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
            default_org: String::new(),
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

    fn provider(kind: ProviderKind, name: &str) -> ProviderConfig {
        ProviderConfig {
            kind,
            name: name.to_owned(),
            client_id: "id".to_owned(),
            client_secret: "secret".to_owned(),
            issuer: None,
            github_endpoints: None,
        }
    }

    #[test]
    fn providers_need_credentials_unique_names_and_an_oidc_issuer() {
        let mut c = CoordinatorConfig::default();
        c.auth.providers = vec![provider(ProviderKind::Github, "github")];
        assert!(c.validate().is_ok());
        c.auth
            .providers
            .push(provider(ProviderKind::Github, "github"));
        assert!(c.validate().is_err(), "duplicate name");
        c.auth.providers = vec![ProviderConfig {
            client_secret: " ".to_owned(),
            ..provider(ProviderKind::Github, "github")
        }];
        assert!(c.validate().is_err(), "no secret");
        c.auth.providers = vec![provider(ProviderKind::Oidc, "sso")];
        assert!(c.validate().is_err(), "oidc without issuer");
        c.auth.providers[0].issuer = Some("https://sso.example".to_owned());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn a_short_csrf_secret_is_refused() {
        let mut c = CoordinatorConfig {
            csrf_secret: Some(vec![1; 31]),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
        c.csrf_secret = Some(vec![1; 32]);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn provider_debug_redacts_the_secret() {
        let p = provider(ProviderKind::Gitlab, "gitlab");
        assert!(!format!("{p:?}").contains("secret\""));
    }

    /// A `[github_actions]` table must name an audience. Accepting GitHub's
    /// default (`https://github.com/<owner>`) would make a token minted for a
    /// *different* service under the same owner replayable here — which is
    /// exactly the mistake a default would invite.
    #[test]
    fn github_actions_requires_an_audience_and_bounded_ttls() {
        let good = GithubActionsConfig {
            audience: "https://fleet.example".to_owned(),
            ..GithubActionsConfig::default()
        };
        let c = CoordinatorConfig {
            github_actions: Some(good.clone()),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_ok());

        for mutate in [
            (|g: &mut GithubActionsConfig| g.audience = "  ".to_owned())
                as fn(&mut GithubActionsConfig),
            |g| g.issuer = String::new(),
            |g| g.jwks_url = String::new(),
            |g| g.jwks_refresh_secs = 0,
            |g| g.workload_token_ttl_secs = 0,
            // Over the 12h cap.
            |g| g.workload_token_ttl_secs = 13 * 3600,
        ] {
            let mut gha = good.clone();
            mutate(&mut gha);
            let c = CoordinatorConfig {
                github_actions: Some(gha),
                ..CoordinatorConfig::default()
            };
            assert!(c.validate().is_err());
        }
    }

    /// A fleet with no CI is a supported deployment; the exchange route then
    /// answers a named 503.
    #[test]
    fn github_actions_is_optional() {
        assert!(CoordinatorConfig::default().github_actions.is_none());
        assert!(CoordinatorConfig::default().validate().is_ok());
    }

    /// `gha` is the reserved namespace CI workload subjects live in, so it must
    /// not also be an org. The same forgs schema check guards every creation
    /// path.
    #[test]
    fn default_org_may_not_be_the_reserved_workload_namespace() {
        let c = CoordinatorConfig {
            default_org: "gha".to_owned(),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }
}
