//! Fleet selector + endpoint resolution from the environment.
//!
//! laze passes only `--chip` (the probe-rs target name) — never a board id or
//! probe serial. The fleet *board* is selected out-of-band via environment
//! variables (additive; no laze change required):
//!
//! | variable                     | meaning                                              |
//! |------------------------------|------------------------------------------------------|
//! | `PROBE_RS_FLEET_BOARD`       | explicit board id (e.g. `nrf52840-dk-3`)             |
//! | `PROBE_RS_FLEET_SELECT`      | constraint expression (e.g. `tag=nrf52 && bluetooth`)|
//! | `PROBE_RS_FLEET_COORDINATOR` | coordinator endpoint (`host:port`)                   |
//! | `PROBE_RS_FLEET_TOKEN`       | bearer token for coordinator auth                    |
//! | `PROBE_RS_FLEET_CLIENT_CERT` | path to client mTLS cert chain (PEM)                 |
//! | `PROBE_RS_FLEET_CLIENT_KEY`  | path to client mTLS private key (PEM)                |
//! | `PROBE_RS_FLEET_CA`          | path to the CA root the coordinator is pinned to     |
//! | `PROBE_RS_FLEET_SUBJECT_ID`  | optional subject-id override (else derived from cert) |
//!
//! Resolution rules:
//!
//! * If **no** fleet variable is set ⇒ [`Resolution::Local`]: invoke the real
//!   local `probe-rs` transparently. Local developer experience is unchanged.
//! * If a board/select selector is set ⇒ [`Resolution::Fleet`], provided the
//!   coordinator endpoint and *some* form of auth (token, or cert+key) are
//!   present. A partial configuration (selector but no coordinator, or
//!   coordinator but no auth) is a hard [`SelectorError`] — we refuse to guess.
//!
//! The environment is read through an injectable [`EnvSource`] so tests never
//! touch the real process environment.

use fleet_proto::ids::BoardName;
use fleet_proto::lease::Constraint;

/// Environment variable names the sidecar consults.
pub mod env {
    /// Explicit board id selector.
    pub const BOARD: &str = "PROBE_RS_FLEET_BOARD";
    /// Constraint-expression selector.
    pub const SELECT: &str = "PROBE_RS_FLEET_SELECT";
    /// Coordinator endpoint (`host:port`).
    pub const COORDINATOR: &str = "PROBE_RS_FLEET_COORDINATOR";
    /// Bearer token for coordinator auth.
    pub const TOKEN: &str = "PROBE_RS_FLEET_TOKEN";
    /// Path to the client mTLS certificate chain (PEM).
    pub const CLIENT_CERT: &str = "PROBE_RS_FLEET_CLIENT_CERT";
    /// Path to the client mTLS private key (PEM).
    pub const CLIENT_KEY: &str = "PROBE_RS_FLEET_CLIENT_KEY";
    /// Path to the pinned CA root (PEM).
    pub const CA: &str = "PROBE_RS_FLEET_CA";
    /// Optional subject-id override (the org is always the coordinator's to
    /// decide).
    pub const SUBJECT_ID: &str = "PROBE_RS_FLEET_SUBJECT_ID";
}

/// A source of environment variables. Implemented for the real process
/// environment and for test-only maps.
pub trait EnvSource {
    /// Look up a variable; `None` if unset (or not valid UTF-8).
    fn get(&self, key: &str) -> Option<String>;
}

/// Reads from the real process environment via [`std::env::var`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl<F> EnvSource for F
where
    F: Fn(&str) -> Option<String>,
{
    fn get(&self, key: &str) -> Option<String> {
        (self)(key)
    }
}

/// Authentication material for the coordinator connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// A bearer token (`PROBE_RS_FLEET_TOKEN`).
    Token(String),
    /// Mutual-TLS client identity: cert chain + key paths, plus the pinned CA.
    Mtls {
        client_cert: String,
        client_key: String,
        ca: Option<String>,
    },
}

/// A fully-resolved fleet configuration: where to lease, how to authenticate,
/// and which board to claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// Coordinator endpoint (`host:port`).
    pub coordinator: String,
    /// How to authenticate to the coordinator.
    pub auth: Auth,
    /// Which board to lease.
    pub select: Constraint,
    /// The calling subject **id**, if explicitly overridden. Otherwise the
    /// coordinator derives it from the client cert at connect time.
    ///
    /// Only the id: a sidecar cannot know or choose its org. The coordinator
    /// assigns the org when it resolves the connection to a `Subject`, which
    /// is what keeps a client from asserting its way into another tenant.
    pub subject_id: Option<String>,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Run the genuine local `probe-rs` transparently (no fleet variables set).
    Local,
    /// Lease a board from the coordinator and proxy the session.
    Fleet(FleetConfig),
}

/// Errors arising from an incomplete or contradictory fleet configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectorError {
    /// A board selector was given but no coordinator endpoint.
    #[error(
        "a fleet board selector is set but {} is not — set the coordinator endpoint",
        env::COORDINATOR
    )]
    MissingCoordinator,
    /// A coordinator/selector is configured but no usable auth was provided.
    #[error(
        "no coordinator auth: set {} or both {} and {}",
        env::TOKEN,
        env::CLIENT_CERT,
        env::CLIENT_KEY
    )]
    MissingAuth,
    /// Both `PROBE_RS_FLEET_BOARD` and `PROBE_RS_FLEET_SELECT` were set.
    #[error(
        "both {} and {} are set — pick one selector",
        env::BOARD,
        env::SELECT
    )]
    AmbiguousSelector,
    /// A coordinator and/or auth was configured but neither board selector was.
    #[error(
        "coordinator/auth is configured but no board selector ({} or {}) is set",
        env::BOARD,
        env::SELECT
    )]
    MissingSelector,
    /// The constraint expression in `PROBE_RS_FLEET_SELECT` was malformed.
    #[error("invalid {} expression: {reason}", env::SELECT)]
    InvalidSelect { reason: String },
    /// Only one of the mTLS cert/key pair was provided.
    #[error(
        "incomplete mTLS identity: set both {} and {}",
        env::CLIENT_CERT,
        env::CLIENT_KEY
    )]
    IncompleteMtls,
}

/// Resolve the fleet configuration from an [`EnvSource`].
///
/// # Errors
///
/// Returns a [`SelectorError`] for any partial / contradictory configuration
/// (see the variants). A completely empty fleet environment resolves cleanly to
/// [`Resolution::Local`].
pub fn resolve(env: &impl EnvSource) -> Result<Resolution, SelectorError> {
    let board = env.get(env::BOARD).filter(|s| !s.is_empty());
    let select = env.get(env::SELECT).filter(|s| !s.is_empty());
    let coordinator = env.get(env::COORDINATOR).filter(|s| !s.is_empty());
    let token = env.get(env::TOKEN).filter(|s| !s.is_empty());
    let client_cert = env.get(env::CLIENT_CERT).filter(|s| !s.is_empty());
    let client_key = env.get(env::CLIENT_KEY).filter(|s| !s.is_empty());
    let ca = env.get(env::CA).filter(|s| !s.is_empty());
    let subject_id = env
        .get(env::SUBJECT_ID)
        .filter(|s| !s.is_empty());

    let any_fleet = board.is_some()
        || select.is_some()
        || coordinator.is_some()
        || token.is_some()
        || client_cert.is_some()
        || client_key.is_some()
        || ca.is_some()
        || subject_id.is_some();

    // No fleet variables at all → transparent local fallback.
    if !any_fleet {
        return Ok(Resolution::Local);
    }

    // Resolve the board selector.
    let constraint = match (board, select) {
        (Some(_), Some(_)) => return Err(SelectorError::AmbiguousSelector),
        (Some(b), None) => Constraint::Board(BoardName(b)),
        (None, Some(expr)) => parse_select(&expr)?,
        (None, None) => return Err(SelectorError::MissingSelector),
    };

    let coordinator = coordinator.ok_or(SelectorError::MissingCoordinator)?;

    // Resolve auth: prefer an explicit token, else an mTLS identity.
    let auth = match (token, client_cert, client_key) {
        (Some(t), _, _) => Auth::Token(t),
        (None, Some(cert), Some(key)) => Auth::Mtls {
            client_cert: cert,
            client_key: key,
            ca,
        },
        (None, Some(_), None) | (None, None, Some(_)) => {
            return Err(SelectorError::IncompleteMtls)
        }
        (None, None, None) => return Err(SelectorError::MissingAuth),
    };

    Ok(Resolution::Fleet(FleetConfig {
        coordinator,
        auth,
        select: constraint,
        subject_id,
    }))
}

/// Parse a `PROBE_RS_FLEET_SELECT` constraint expression into a
/// [`Constraint`].
///
/// Supported grammar (small by design; the coordinator does the real matching):
///
/// * `tag=<name>` or just `<name>` — a single required tag.
/// * `<a> && <b> && …` — a conjunction of required tags.
/// * `chip=<name>` — match by probe-rs chip name.
///
/// Tag conjunctions map to [`Constraint::Tags`]; a sole `chip=` term maps to
/// [`Constraint::Chip`]. Mixing `chip=` with tags, or an empty expression, is
/// an error — those cannot be expressed by the (deliberately narrow) wire
/// [`Constraint`] enum.
fn parse_select(expr: &str) -> Result<Constraint, SelectorError> {
    let terms: Vec<&str> = expr
        .split("&&")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    if terms.is_empty() {
        return Err(SelectorError::InvalidSelect { reason: "expression is empty".to_owned() });
    }

    // A single `chip=<name>` term selects by chip.
    if terms.len() == 1 {
        if let Some(chip) = terms[0].strip_prefix("chip=") {
            let chip = chip.trim();
            if chip.is_empty() {
                return Err(SelectorError::InvalidSelect { reason: "empty chip name".to_owned() });
            }
            return Ok(Constraint::Chip(chip.to_owned()));
        }
    }

    // Otherwise every term must be a tag (`tag=<name>` or bare `<name>`).
    let mut tags = Vec::with_capacity(terms.len());
    for term in terms {
        if term.starts_with("chip=") {
            return Err(SelectorError::InvalidSelect {
                reason: "chip= cannot be combined with tags".to_owned(),
            });
        }
        let tag = term.strip_prefix("tag=").unwrap_or(term).trim();
        if tag.is_empty() {
            return Err(SelectorError::InvalidSelect { reason: "empty tag".to_owned() });
        }
        if tag.contains('=') {
            return Err(SelectorError::InvalidSelect {
                reason: format!("unsupported term `{term}`"),
            });
        }
        tags.push(tag.to_owned());
    }
    Ok(Constraint::Tags(tags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A map-backed [`EnvSource`] for tests.
    struct MapEnv(HashMap<String, String>);

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        }
    }

    impl EnvSource for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    #[test]
    fn no_fleet_env_resolves_to_local() {
        let env = MapEnv::new(&[]);
        assert_eq!(resolve(&env).unwrap(), Resolution::Local);
    }

    #[test]
    fn unrelated_env_still_local() {
        // A function-based EnvSource that returns None for everything.
        let env = |_: &str| None;
        assert_eq!(resolve(&env).unwrap(), Resolution::Local);
    }

    #[test]
    fn board_id_with_token() {
        let env = MapEnv::new(&[
            (env::BOARD, "nrf52840-dk-3"),
            (env::COORDINATOR, "coord.example:4443"),
            (env::TOKEN, "secret"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(cfg.coordinator, "coord.example:4443");
        assert_eq!(cfg.select, Constraint::Board(BoardName("nrf52840-dk-3".to_owned())));
        assert_eq!(cfg.auth, Auth::Token("secret".to_owned()));
        assert_eq!(cfg.subject_id, None);
    }

    #[test]
    fn select_expr_with_mtls() {
        let env = MapEnv::new(&[
            (env::SELECT, "tag=nrf52 && bluetooth"),
            (env::COORDINATOR, "coord:4443"),
            (env::CLIENT_CERT, "/c/cert.pem"),
            (env::CLIENT_KEY, "/c/key.pem"),
            (env::CA, "/c/ca.pem"),
            (env::SUBJECT_ID, "ci-bot"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(
            cfg.select,
            Constraint::Tags(vec!["nrf52".to_owned(), "bluetooth".to_owned()])
        );
        assert_eq!(
            cfg.auth,
            Auth::Mtls {
                client_cert: "/c/cert.pem".to_owned(),
                client_key: "/c/key.pem".to_owned(),
                ca: Some("/c/ca.pem".to_owned()),
            }
        );
        assert_eq!(cfg.subject_id, Some("ci-bot".to_owned()));
    }

    #[test]
    fn select_chip_expr() {
        let env = MapEnv::new(&[
            (env::SELECT, "chip=nRF52840_xxAA"),
            (env::COORDINATOR, "c:1"),
            (env::TOKEN, "t"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(cfg.select, Constraint::Chip("nRF52840_xxAA".to_owned()));
    }

    #[test]
    fn missing_coordinator_is_error() {
        let env = MapEnv::new(&[(env::BOARD, "b"), (env::TOKEN, "t")]);
        assert_eq!(resolve(&env), Err(SelectorError::MissingCoordinator));
    }

    #[test]
    fn missing_auth_is_error() {
        let env = MapEnv::new(&[(env::BOARD, "b"), (env::COORDINATOR, "c:1")]);
        assert_eq!(resolve(&env), Err(SelectorError::MissingAuth));
    }

    #[test]
    fn incomplete_mtls_is_error() {
        let env = MapEnv::new(&[
            (env::BOARD, "b"),
            (env::COORDINATOR, "c:1"),
            (env::CLIENT_CERT, "/c/cert.pem"),
        ]);
        assert_eq!(resolve(&env), Err(SelectorError::IncompleteMtls));
    }

    #[test]
    fn ambiguous_selector_is_error() {
        let env = MapEnv::new(&[
            (env::BOARD, "b"),
            (env::SELECT, "tag=x"),
            (env::COORDINATOR, "c:1"),
            (env::TOKEN, "t"),
        ]);
        assert_eq!(resolve(&env), Err(SelectorError::AmbiguousSelector));
    }

    #[test]
    fn coordinator_without_selector_is_error() {
        // Coordinator + auth set but no board selector.
        let env = MapEnv::new(&[(env::COORDINATOR, "c:1"), (env::TOKEN, "t")]);
        assert_eq!(resolve(&env), Err(SelectorError::MissingSelector));
    }

    #[test]
    fn token_preferred_over_mtls() {
        let env = MapEnv::new(&[
            (env::BOARD, "b"),
            (env::COORDINATOR, "c:1"),
            (env::TOKEN, "t"),
            (env::CLIENT_CERT, "/c/cert.pem"),
            (env::CLIENT_KEY, "/c/key.pem"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(cfg.auth, Auth::Token("t".to_owned()));
    }

    #[test]
    fn empty_values_treated_as_unset() {
        // Empty strings must not count as "set" — otherwise an exported-but-
        // empty var would wrongly trip fleet mode.
        let env = MapEnv::new(&[(env::BOARD, ""), (env::COORDINATOR, "")]);
        assert_eq!(resolve(&env).unwrap(), Resolution::Local);
    }

    #[test]
    fn bare_tag_select() {
        assert_eq!(
            parse_select("bluetooth").unwrap(),
            Constraint::Tags(vec!["bluetooth".to_owned()])
        );
    }

    #[test]
    fn empty_select_is_error() {
        assert!(matches!(
            parse_select("   "),
            Err(SelectorError::InvalidSelect { .. })
        ));
    }

    #[test]
    fn chip_mixed_with_tags_is_error() {
        assert!(matches!(
            parse_select("chip=x && tag=y"),
            Err(SelectorError::InvalidSelect { .. })
        ));
    }
}
