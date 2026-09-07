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

/// The GitHub OAuth app the coordinator brokers user login with.
///
/// **`OAuth2`, not OIDC.** GitHub user login has no discovery document, no ID
/// token and no JWKS; both flows yield an *access token* and identity comes
/// from `GET /user`. (GitHub Actions workload identity *is* real OIDC — a
/// different verifier, a different task.)
///
/// Two front doors, one app: the CLI's device flow (RFC 8628, no `redirect_uri`
/// at all) and the browser's authorization-code flow (`docs/web-ui.md` D1). The
/// device flow needs no per-deployment registration; the browser one needs
/// exactly one, which is what [`callback_registered`](Self::callback_registered)
/// asserts. A deployment that skips it still has a working login — the web UI
/// falls back to showing a device code — so the browser path is a nicety rather
/// than a new requirement.
///
/// The endpoint URLs are configurable so the integration tests can point the
/// flows at a loopback stub — the only way to exercise them without GitHub.
#[derive(Debug, Clone)]
pub struct GithubConfig {
    /// The OAuth app's client id. Not a secret (it appears in the device-flow
    /// request and in the browser redirect), but without it there is no flow.
    pub client_id: String,
    /// The OAuth app's client secret, when the app requires one.
    ///
    /// OAuth Apps do not need it for the device flow; some GitHub App
    /// configurations do. It becomes **required** once
    /// [`callback_registered`](Self::callback_registered) is true: GitHub's
    /// token endpoint refuses the authorization-code exchange without it, and
    /// GitHub implements no PKCE, so the secret is also what makes an
    /// intercepted code unspendable. It never leaves this process.
    pub client_secret: Option<String>,
    /// The OAuth scope requested. Empty is correct for identity-only login:
    /// `GET /user` needs no scope, and asking for more than we use is a
    /// permission the user cannot get back.
    pub scope: String,
    /// `POST` endpoint that starts a device flow.
    pub device_code_url: String,
    /// `POST` endpoint that redeems a device code — or a browser authorization
    /// code — for an access token.
    pub access_token_url: String,
    /// Base URL of the GitHub REST API (`GET {api_base}/user`).
    pub api_base: String,
    /// Browser-facing endpoint the `/auth/github/start` redirect targets.
    ///
    /// Overridable exactly like the three URLs above, for GitHub Enterprise or
    /// a loopback test stub; that overridability is what lets the integration
    /// tests exercise the browser flow at all.
    pub authorize_url: String,
    /// The operator asserting that `<public_url>/auth/github/callback` is
    /// registered as a callback URL in the OAuth app.
    ///
    /// Browser authorization-code login is offered **only** when this is true.
    /// It is the one per-deployment setup step the device flow did not need,
    /// and nothing the coordinator can discover for itself — GitHub does not
    /// expose an app's registered callbacks to the app. Default `false`, so a
    /// deployment that has not done the registration falls back to the in-page
    /// device-code login rather than sending every user into a redirect that
    /// dead-ends on GitHub's "`redirect_uri` is not associated with this
    /// application" page.
    pub callback_registered: bool,
}

/// The GitHub Actions OIDC issuer the coordinator accepts workload tokens
/// from (architecture §6.7).
///
/// **This one really is OIDC**, unlike [`GithubConfig`] above: signed JWTs, a
/// JWKS endpoint, and claims to verify. The two are independent — a fleet may
/// have CI without user login, or the reverse.
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
    /// `login --fleet-url` / `agent up --fleet-url`.
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
        if self.default_org.0.is_empty() {
            return Err(CoordinatorError::Config(
                "default_org must be non-empty".to_owned(),
            ));
        }
        // `gha` is the reserved namespace a CI workload's subject key lives in
        // (architecture §6.7, `fleet_proto::ids::WORKLOAD_NS_GHA`). Letting an
        // operator point `default_org` at it would put real tenant objects in
        // a namespace whose whole meaning is "not a tenant". This is the
        // second belt; the first is `Db::ensure_org`, which refuses the id at
        // *every* org-creation path — a reserved name only one of the two
        // respects is a trap for the next change.
        if self.default_org.0 == fleet_proto::ids::WORKLOAD_NS_GHA {
            return Err(CoordinatorError::Config(format!(
                "default_org must not be `{}`: that namespace is reserved for CI \
                 workload subjects (architecture §6.7)",
                fleet_proto::ids::WORKLOAD_NS_GHA
            )));
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
                // Joined to the three above rather than checked separately:
                // an empty authorize endpoint is the same class of mistake,
                // and it would surface as a 302 to a bare query string.
                ("github.authorize_url", &gh.authorize_url),
            ] {
                if value.trim().is_empty() {
                    return Err(CoordinatorError::Config(format!(
                        "{label} must be non-empty"
                    )));
                }
            }
            // Opting into browser login without a secret is a login that always
            // fails at its last step: GitHub's token endpoint refuses the
            // authorization-code exchange without `client_secret`, and GitHub
            // implements no PKCE, so there is no verifier standing in for it.
            // Refused here, where the operator can act on it, rather than at
            // the callback, where every user sees an opaque error.
            if gh.callback_registered && gh.client_secret.is_none() {
                return Err(CoordinatorError::Config(
                    "github.client_secret is required when github.callback_registered = true: \
                     GitHub refuses the authorization-code exchange without it (and implements \
                     no PKCE). Set the secret, or set callback_registered = false to fall back \
                     to the device flow."
                        .to_owned(),
                ));
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
            pending_node_ttl_secs: 15 * 60,
            max_pending_nodes: 256,
            default_org: OrgId(crate::state::DEFAULT_ORG_ID.to_owned()),
            github: None,
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
            authorize_url: "https://github.com/login/oauth/authorize".to_owned(),
            callback_registered: false,
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
                ..good.clone()
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());

        // The browser flow's endpoint is checked with the other three: an empty
        // one would 302 the user at a bare query string.
        let c = CoordinatorConfig {
            github: Some(GithubConfig {
                authorize_url: "  ".to_owned(),
                ..good
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }

    /// `callback_registered = true` promises a browser login; without a client
    /// secret that login always fails at its last step, because GitHub refuses
    /// the authorization-code grant without one and implements no PKCE to stand
    /// in for it. The failure is invisible until a real user tries to log in,
    /// which is why it is a startup error.
    #[test]
    fn callback_registered_requires_a_client_secret() {
        let base = GithubConfig {
            client_id: "Iv1.abc".to_owned(),
            client_secret: None,
            scope: String::new(),
            device_code_url: "https://github.com/login/device/code".to_owned(),
            access_token_url: "https://github.com/login/oauth/access_token".to_owned(),
            api_base: "https://api.github.com".to_owned(),
            authorize_url: "https://github.com/login/oauth/authorize".to_owned(),
            callback_registered: true,
        };
        let c = CoordinatorConfig {
            github: Some(base.clone()),
            ..CoordinatorConfig::default()
        };
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("client_secret"), "{err}");
        // The message has to carry the remediation, or an operator's only move
        // is to guess which of the two knobs to turn.
        assert!(err.contains("callback_registered = false"), "{err}");

        // With a secret, the same table is valid.
        let c = CoordinatorConfig {
            github: Some(GithubConfig {
                client_secret: Some("s3cret".to_owned()),
                ..base.clone()
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_ok());

        // And a deployment that has not registered the callback needs none:
        // the device flow is the fallback, and it asks for no secret.
        let c = CoordinatorConfig {
            github: Some(GithubConfig {
                callback_registered: false,
                ..base
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_ok());
    }

    /// No `[github]` table is a supported deployment (air-gapped / dev), not an
    /// invalid one.
    #[test]
    fn github_is_optional() {
        assert!(CoordinatorConfig::default().github.is_none());
        assert!(CoordinatorConfig::default().validate().is_ok());
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
    /// not also be a tenant id. This is the config half of the fence;
    /// `Db::ensure_org` is the other half, and both are needed — a reserved
    /// name that only one creation path respects is worse than none.
    #[test]
    fn default_org_may_not_be_the_reserved_workload_namespace() {
        let c = CoordinatorConfig {
            default_org: OrgId(fleet_proto::ids::WORKLOAD_NS_GHA.to_owned()),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }
}
