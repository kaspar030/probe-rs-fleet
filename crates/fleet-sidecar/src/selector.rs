//! Fleet selector + endpoint resolution from the environment.
//!
//! laze passes only `--chip` (the probe-rs target name) — never a board id or
//! probe serial. The fleet *board* is selected out-of-band via environment
//! variables (additive; no laze change required):
//!
//! | variable                          | meaning                                              |
//! |-----------------------------------|------------------------------------------------------|
//! | `PROBE_RS_FLEET_BOARD`            | board **model** (e.g. `nrf52840dk`) — any board of that type |
//! | `PROBE_RS_FLEET_ID`               | one specific board, by node-local id (e.g. `nrf52840-dk-3`) |
//! | `PROBE_RS_FLEET_SELECT`           | constraint expression (e.g. `tag=nrf52 && bluetooth`)|
//! | `PROBE_RS_FLEET_COORDINATOR`      | coordinator URL (`https://fleet.example`, or `host:port`) |
//! | `PROBE_RS_FLEET_TOKEN`            | the bearer session token                             |
//! | `PROBE_RS_FLEET_SERVER_CERT_SHA256` | optional pinned server-cert hash (self-hosted)     |
//!
//! Resolution rules:
//!
//! * If **no** fleet variable is set ⇒ [`Resolution::Local`]: invoke the real
//!   local `probe-rs` transparently. Local developer experience is unchanged.
//! * If a board/id/select selector is set ⇒ [`Resolution::Fleet`], provided the
//!   coordinator URL and a token are both present. A partial configuration
//!   (selector but no coordinator, or coordinator but no token) is a hard
//!   [`SelectorError`] — we refuse to guess. At most **one** of the three
//!   selector variables may be set.
//!
//! # What is deliberately *not* here any more
//!
//! Revision 2 deleted `PROBE_RS_FLEET_CLIENT_CERT` / `_CLIENT_KEY` / `_CA` with
//! the private CA, and `PROBE_RS_FLEET_SUBJECT_ID` with them. That last one was
//! not merely dead config: it let a client assert its own identity to the
//! coordinator. The subject now comes from the token and from nowhere else.
//!
//! The environment is read through an injectable [`EnvSource`] so tests never
//! touch the real process environment.
//!
//! That injectability is also how the CLI selector flags work: this crate still
//! resolves purely from an `EnvSource`, but `probe-rs-fleet sidecar --board` /
//! `--id` / `--select` layers the flag over the process environment in
//! `fleet-bin`
//! (`roles::sidecar::SelectorFlags`). The flag wins and *replaces all three*
//! selector variables, so it never produces [`SelectorError::AmbiguousSelector`]
//! against a stale one; `PROBE_RS_FLEET_CAPABILITY` is not intercepted, so a
//! capability token plus a flag is still
//! [`SelectorError::CapabilityWithSelector`]. The argv0 `probe-rs` shim carries
//! no flags at all (it forwards every argument verbatim to stay transparent to
//! laze), so there the environment remains the only mechanism.

use fleet_proto::ids::BoardName;
use fleet_proto::lease::Constraint;

/// Environment variable names the sidecar consults.
pub mod env {
    /// Board **model** selector: any board of this board type, e.g.
    /// `nrf52840dk`. The word "board" means the model on every surface — this
    /// variable, the `board=` selector term and `sidecar --board`.
    pub const BOARD: &str = "PROBE_RS_FLEET_BOARD";
    /// Explicit board **instance** selector: one board, by node-local id.
    pub const ID: &str = "PROBE_RS_FLEET_ID";
    /// Constraint-expression selector.
    pub const SELECT: &str = "PROBE_RS_FLEET_SELECT";
    /// Coordinator base URL (`https://host[:port]`, or a bare `host:port`).
    pub const COORDINATOR: &str = "PROBE_RS_FLEET_COORDINATOR";
    /// The bearer session token.
    pub const TOKEN: &str = "PROBE_RS_FLEET_TOKEN";
    /// Optional pinned coordinator server-certificate SHA-256 (64 hex chars),
    /// for a self-hosted deployment with no publicly trusted certificate.
    pub const SERVER_CERT_SHA256: &str = "PROBE_RS_FLEET_SERVER_CERT_SHA256";
    /// A **capability token** (hex), from `probe-rs-fleet ctl delegate`.
    ///
    /// The sandboxed-client credential (architecture §6.5). It is not a fleet
    /// identity: it authorises exactly one lease on exactly one board, expires
    /// with that lease, and can be revoked by releasing it. Setting it selects
    /// the delegated path; a board selector must **not** also be set, because
    /// the board is inside the token.
    pub const CAPABILITY: &str = "PROBE_RS_FLEET_CAPABILITY";
    /// Set to a non-empty value to disable the cross-invocation lease store
    /// ([`crate::lease_store`]) entirely.
    ///
    /// This restores the pre-cache behaviour exactly: every invocation leases a
    /// board of its own and releases it on the way out, so no board is ever
    /// held between two `probe-rs` commands. The escape hatch for a shared
    /// workstation, or for debugging the cache itself.
    pub const NO_LEASE_CACHE: &str = "PROBE_RS_FLEET_NO_LEASE_CACHE";
    /// How long, in seconds, to wait for a queued lease request to be promoted
    /// before giving up. Default [`super::DEFAULT_QUEUE_WAIT_SECS`].
    ///
    /// A **client-side** bound, not a coordinator policy knob: how long *this*
    /// invocation is willing to sit in the queue is the caller's business, and
    /// a CI leg, an interactive `probe-rs run` and a script have different
    /// answers. `0` disables waiting, restoring the fail-fast behaviour.
    pub const QUEUE_WAIT: &str = "PROBE_RS_FLEET_QUEUE_WAIT";
}

/// How long a queued lease request waits for promotion by default: 5 minutes.
///
/// "Low minutes" is the target: long enough that a matrix leg wider than the
/// fleet gets its turn once the legs ahead of it finish a flash-and-test cycle,
/// short enough that a genuinely stuck job fails inside a typical CI step
/// timeout instead of burning the whole budget.
///
/// Safe against both ends' liveness checks: the coordinator pings every 20s
/// with a 60s pong timeout, tungstenite answers inbound pings automatically,
/// and the sidecar's reader task keeps looping throughout the wait — so the
/// *transport* is never idle for more than 20s even though the *application*
/// is idle for minutes. If this default is ever raised past a proxy's idle
/// timeout, that is the reasoning to re-check.
pub const DEFAULT_QUEUE_WAIT_SECS: u64 = 300;

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

/// A fully-resolved fleet configuration: where to lease, how to authenticate,
/// and which board to claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// Coordinator base URL.
    pub coordinator: String,
    /// The bearer token presented on the `WebSocket` upgrade.
    ///
    /// One credential, whatever the principal is: a user session token, or a
    /// **workload token** exchanged per CI job (architecture §6.7, obtained by
    /// `probe-rs-fleet ci login`). The coordinator resolves it to a subject;
    /// the client has no say in who it is — which is exactly why the CI path
    /// needed no change here at all. A workload token arrives in
    /// `PROBE_RS_FLEET_TOKEN` like any other.
    pub token: String,
    /// Which board to lease.
    pub select: Constraint,
    /// Optional pinned coordinator server-certificate SHA-256, as 64 lowercase
    /// hex characters.
    pub server_cert_sha256: Option<String>,
    /// How long to wait for a queued lease request to be promoted, in seconds;
    /// `0` means do not wait.
    ///
    /// From [`env::QUEUE_WAIT`], defaulting to
    /// [`DEFAULT_QUEUE_WAIT_SECS`].
    pub queue_wait_secs: u64,
}

impl FleetConfig {
    /// The pinned server-certificate hash, decoded.
    #[must_use]
    pub fn server_pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }
}

/// A resolved **delegated** configuration: a sandboxed client with a capability
/// token and nothing else (architecture §6.5).
///
/// Note what is absent, deliberately: no session token, no selector, no
/// identity. The board and the lease are inside the token, which is also the
/// only thing that authorises anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedConfig {
    /// Coordinator base URL.
    pub coordinator: String,
    /// The hex-encoded capability token, presented as the bearer on
    /// `/delegate`.
    pub capability: String,
    /// Optional pinned coordinator server-certificate SHA-256.
    pub server_cert_sha256: Option<String>,
}

impl DelegatedConfig {
    /// The pinned server-certificate hash, decoded.
    #[must_use]
    pub fn server_pin(&self) -> Option<[u8; 32]> {
        self.server_cert_sha256
            .as_deref()
            .and_then(fleet_tls::parse_fingerprint)
    }

    /// The lease id the token authorises, decoded locally.
    ///
    /// Decode-only — there is no signature check here, and there must not be:
    /// the sandbox holds no public key, and the *coordinator* is what verifies
    /// the token. This only saves a round trip to learn which lease to open a
    /// channel on; a forged token gets a `401` at the door regardless.
    #[must_use]
    pub fn lease(&self) -> Option<fleet_proto::LeaseId> {
        let wire = decode_hex(&self.capability)?;
        let signed = fleet_proto::token::SignedToken::from_wire(&wire).ok()?;
        signed.decode_token().ok().map(|t| t.lease)
    }
}

/// Decode a hex string into bytes.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Run the genuine local `probe-rs` transparently (no fleet variables set).
    Local,
    /// Lease a board from the coordinator and proxy the session.
    Fleet(FleetConfig),
    /// Use a board already leased for us, via a delegated capability token.
    Delegated(DelegatedConfig),
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
    /// A coordinator/selector is configured but no bearer token was provided.
    #[error("no coordinator credential: set {}", env::TOKEN)]
    MissingAuth,
    /// More than one of `PROBE_RS_FLEET_BOARD`, `PROBE_RS_FLEET_ID` and
    /// `PROBE_RS_FLEET_SELECT` was set.
    #[error(
        "more than one of {}, {} and {} is set — pick one selector",
        env::BOARD,
        env::ID,
        env::SELECT
    )]
    AmbiguousSelector,
    /// A coordinator and/or auth was configured but no board selector was.
    #[error(
        "coordinator/auth is configured but no board selector ({}, {} or {}) is set",
        env::BOARD,
        env::ID,
        env::SELECT
    )]
    MissingSelector,
    /// The constraint expression in `PROBE_RS_FLEET_SELECT` was malformed.
    #[error("invalid {} expression: {reason}", env::SELECT)]
    InvalidSelect { reason: String },
    /// The pinned server-certificate hash was not 64 hex characters.
    ///
    /// Rejected rather than ignored: silently dropping a malformed pin would
    /// downgrade a deliberately pinned deployment to `WebPKI` verification.
    #[error("invalid {}: expected 64 hex characters", env::SERVER_CERT_SHA256)]
    InvalidPin,
    /// A capability token was set *and* a board selector.
    ///
    /// Not merely redundant: the board is inside the token, so a selector could
    /// only ever disagree with it, and honouring either one silently would make
    /// which board you got depend on a guess.
    #[error(
        "{} selects a board already leased for you — do not also set {}, {} or {}",
        env::CAPABILITY,
        env::BOARD,
        env::ID,
        env::SELECT
    )]
    CapabilityWithSelector,
    /// A capability token was set together with a session token.
    ///
    /// Refused so a sandbox cannot be handed a fleet identity by accident: the
    /// whole point of delegation is that it has none.
    #[error(
        "{} and {} are different credentials — set exactly one",
        env::CAPABILITY,
        env::TOKEN
    )]
    CapabilityWithToken,
    /// The capability token was not decodable as a signed capability token.
    ///
    /// Decoded (not verified) locally only to learn which lease to open a
    /// channel on. A token that will not decode cannot be used, and saying so
    /// here is far more useful than a `401` from the coordinator.
    #[error("invalid {}: not a hex-encoded capability token", env::CAPABILITY)]
    InvalidCapability,
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
    let id = env.get(env::ID).filter(|s| !s.is_empty());
    let select = env.get(env::SELECT).filter(|s| !s.is_empty());
    let coordinator = env.get(env::COORDINATOR).filter(|s| !s.is_empty());
    let token = env.get(env::TOKEN).filter(|s| !s.is_empty());
    let capability = env.get(env::CAPABILITY).filter(|s| !s.is_empty());
    let pin = env.get(env::SERVER_CERT_SHA256).filter(|s| !s.is_empty());
    // A malformed value falls back to the default rather than failing the
    // invocation: this tunes patience, and refusing to run over it would be a
    // worse outcome than waiting the default five minutes.
    let queue_wait_secs = env
        .get(env::QUEUE_WAIT)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_QUEUE_WAIT_SECS);

    let any_fleet = board.is_some()
        || id.is_some()
        || select.is_some()
        || coordinator.is_some()
        || token.is_some()
        || capability.is_some()
        || pin.is_some();

    // No fleet variables at all → transparent local fallback.
    if !any_fleet {
        return Ok(Resolution::Local);
    }

    if let Some(pin) = &pin {
        if fleet_tls::parse_fingerprint(pin).is_none() {
            return Err(SelectorError::InvalidPin);
        }
    }

    // The delegated path: a capability token names its own board, so a selector
    // or a session token alongside it is a contradiction rather than extra
    // information.
    if let Some(capability) = capability {
        if board.is_some() || id.is_some() || select.is_some() {
            return Err(SelectorError::CapabilityWithSelector);
        }
        if token.is_some() {
            return Err(SelectorError::CapabilityWithToken);
        }
        let coordinator = coordinator.ok_or(SelectorError::MissingCoordinator)?;
        return Ok(Resolution::Delegated(DelegatedConfig {
            coordinator,
            capability,
            server_cert_sha256: pin,
        }));
    }

    // Resolve the board selector: exactly one of the three variables, never
    // two — `board=` (model), `id=` (instance) and a full expression are
    // different questions, and guessing which one the operator meant is how a
    // job silently lands on the wrong board.
    let constraint = match (board, id, select) {
        (Some(model), None, None) => Constraint::Model(model),
        (None, Some(name), None) => Constraint::Id(BoardName(name)),
        (None, None, Some(expr)) => parse_select(&expr)?,
        (None, None, None) => return Err(SelectorError::MissingSelector),
        _ => return Err(SelectorError::AmbiguousSelector),
    };

    let coordinator = coordinator.ok_or(SelectorError::MissingCoordinator)?;
    let token = token.ok_or(SelectorError::MissingAuth)?;

    Ok(Resolution::Fleet(FleetConfig {
        coordinator,
        token,
        select: constraint,
        server_cert_sha256: pin,
        queue_wait_secs,
    }))
}

/// Parse a `PROBE_RS_FLEET_SELECT` constraint expression into a
/// [`Constraint`].
///
/// A thin delegate to [`fleet_proto::lease::parse_constraint`], the fleet's one
/// selector grammar (architecture §6.5), where a bare term is a **tag** —
/// `PROBE_RS_FLEET_SELECT=nrf52 && bluetooth` describes a set of boards.
/// `board=<model>` selects any board of a model and `id=<name>` one specific
/// board; `PROBE_RS_FLEET_BOARD` / `PROBE_RS_FLEET_ID` are the shorthands for
/// those two.
fn parse_select(expr: &str) -> Result<Constraint, SelectorError> {
    fleet_proto::lease::parse_constraint(expr).map_err(|e| SelectorError::InvalidSelect {
        reason: e.to_string(),
    })
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

    /// The queue wait defaults to five minutes, is overridable, and treats a
    /// malformed value as "use the default" rather than failing the run — it
    /// tunes patience, and refusing to start over it would be the worse
    /// outcome.
    #[test]
    fn the_queue_wait_defaults_and_can_be_overridden() {
        let base = [
            (env::ID, "b1"),
            (env::COORDINATOR, "coord.example:4443"),
            (env::TOKEN, "secret"),
        ];
        let fleet = |pairs: &[(&str, &str)]| {
            let Resolution::Fleet(cfg) = resolve(&MapEnv::new(pairs)).unwrap() else {
                panic!("expected Fleet");
            };
            cfg
        };

        assert_eq!(
            fleet(&base).queue_wait_secs,
            DEFAULT_QUEUE_WAIT_SECS,
            "low minutes by default"
        );

        let mut with_wait = base.to_vec();
        with_wait.push((env::QUEUE_WAIT, "30"));
        assert_eq!(fleet(&with_wait).queue_wait_secs, 30);

        // 0 is the documented escape hatch: fail fast on contention.
        let mut no_wait = base.to_vec();
        no_wait.push((env::QUEUE_WAIT, "0"));
        assert_eq!(fleet(&no_wait).queue_wait_secs, 0);

        let mut junk = base.to_vec();
        junk.push((env::QUEUE_WAIT, "soon"));
        assert_eq!(fleet(&junk).queue_wait_secs, DEFAULT_QUEUE_WAIT_SECS);
    }

    #[test]
    fn unrelated_env_still_local() {
        // A function-based EnvSource that returns None for everything.
        let env = |_: &str| None;
        assert_eq!(resolve(&env).unwrap(), Resolution::Local);
    }

    #[test]
    fn board_var_selects_a_model() {
        let env = MapEnv::new(&[
            (env::BOARD, "nrf52840dk"),
            (env::COORDINATOR, "coord.example:4443"),
            (env::TOKEN, "secret"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(cfg.coordinator, "coord.example:4443");
        assert_eq!(cfg.select, Constraint::Model("nrf52840dk".to_owned()));
        assert_eq!(cfg.token, "secret");
        assert!(cfg.server_pin().is_none());
    }

    #[test]
    fn id_var_selects_one_board() {
        let env = MapEnv::new(&[
            (env::ID, "nrf52840-dk-3"),
            (env::COORDINATOR, "coord.example:4443"),
            (env::TOKEN, "secret"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(
            cfg.select,
            Constraint::Id(BoardName("nrf52840-dk-3".to_owned()))
        );
    }

    #[test]
    fn select_expr_with_pin() {
        let pin = "ab".repeat(32);
        let env = MapEnv::new(&[
            (env::SELECT, "tag=nrf52 && bluetooth"),
            (env::COORDINATOR, "https://coord.example"),
            (env::TOKEN, "prfs1_secret"),
            (env::SERVER_CERT_SHA256, &pin),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        assert_eq!(
            cfg.select,
            Constraint::Tags(vec!["nrf52".to_owned(), "bluetooth".to_owned()])
        );
        assert_eq!(cfg.token, "prfs1_secret");
        assert_eq!(cfg.server_pin(), Some([0xabu8; 32]));
    }

    /// A malformed pin is an error, not a shrug: ignoring it would quietly
    /// downgrade a pinned self-hosted deployment to `WebPKI` verification.
    #[test]
    fn malformed_pin_is_an_error() {
        let env = MapEnv::new(&[
            (env::BOARD, "b"),
            (env::COORDINATOR, "c:1"),
            (env::TOKEN, "t"),
            (env::SERVER_CERT_SHA256, "not-a-hash"),
        ]);
        assert_eq!(resolve(&env), Err(SelectorError::InvalidPin));
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

    /// Any two of the three selector variables is a refusal, never a
    /// precedence rule: which board you got must not depend on a guess.
    #[test]
    fn ambiguous_selector_is_error() {
        let pairs = [
            [(env::BOARD, "nrf52840dk"), (env::SELECT, "tag=x")],
            [(env::BOARD, "nrf52840dk"), (env::ID, "b1")],
            [(env::ID, "b1"), (env::SELECT, "tag=x")],
        ];
        for pair in pairs {
            let env = MapEnv::new(&[
                pair[0],
                pair[1],
                (env::COORDINATOR, "c:1"),
                (env::TOKEN, "t"),
            ]);
            assert_eq!(
                resolve(&env),
                Err(SelectorError::AmbiguousSelector),
                "{} + {} must be ambiguous",
                pair[0].0,
                pair[1].0
            );
        }
        // All three at once, too.
        let env = MapEnv::new(&[
            (env::BOARD, "nrf52840dk"),
            (env::ID, "b1"),
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

    /// The two shorthand variables mean exactly what the corresponding
    /// expression terms mean; `PROBE_RS_FLEET_SELECT` can spell either.
    #[test]
    fn the_shorthand_vars_match_the_expression_terms() {
        assert_eq!(
            parse_select("board=nrf52840dk").unwrap(),
            Constraint::Model("nrf52840dk".to_owned())
        );
        assert_eq!(
            parse_select("id=nrf52840-dk-3").unwrap(),
            Constraint::Id(BoardName("nrf52840-dk-3".to_owned()))
        );
    }

    /// The deleted `PROBE_RS_FLEET_SUBJECT_ID` let a client assert its own
    /// identity. Setting it now must have no effect whatsoever — in particular
    /// it must not trip fleet mode on its own, which would be a confusing way to
    /// discover the variable is gone.
    #[test]
    fn the_deleted_subject_id_override_has_no_effect() {
        let env = MapEnv::new(&[("PROBE_RS_FLEET_SUBJECT_ID", "root")]);
        assert_eq!(resolve(&env).unwrap(), Resolution::Local);

        let env = MapEnv::new(&[
            (env::BOARD, "nrf52840dk"),
            (env::COORDINATOR, "c:1"),
            (env::TOKEN, "t"),
            ("PROBE_RS_FLEET_SUBJECT_ID", "root"),
        ]);
        let Resolution::Fleet(cfg) = resolve(&env).unwrap() else {
            panic!("expected Fleet");
        };
        // The struct has no place to put it; identity comes from the token.
        assert_eq!(cfg.token, "t");
    }

    #[test]
    fn empty_values_treated_as_unset() {
        // Empty strings must not count as "set" — otherwise an exported-but-
        // empty var would wrongly trip fleet mode.
        let env = MapEnv::new(&[(env::BOARD, ""), (env::ID, ""), (env::COORDINATOR, "")]);
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

    /// The `PROBE_RS_FLEET_SELECT` surface: the wildcard refusal must reach
    /// the user through `SelectorError::InvalidSelect`'s reason, not be
    /// flattened into a generic "invalid selector".
    #[test]
    fn a_wildcard_select_names_the_real_answer() {
        let Err(SelectorError::InvalidSelect { reason }) = parse_select("*") else {
            panic!("`*` should be refused");
        };
        assert!(reason.contains("no wildcard"), "{reason}");

        let env = MapEnv::new(&[("PROBE_RS_FLEET_SELECT", "*")]);
        let Err(SelectorError::InvalidSelect { reason }) = resolve(&env) else {
            panic!("`PROBE_RS_FLEET_SELECT=*` should be refused");
        };
        assert!(reason.contains("no wildcard"), "{reason}");
    }

    #[test]
    fn chip_mixed_with_tags_is_error() {
        assert!(matches!(
            parse_select("chip=x && tag=y"),
            Err(SelectorError::InvalidSelect { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // The delegated path (architecture §6.5)
    // -----------------------------------------------------------------------

    #[test]
    fn a_capability_token_resolves_to_the_delegated_path() {
        let env = MapEnv::new(&[
            (env::CAPABILITY, "deadbeef"),
            (env::COORDINATOR, "https://coord.example"),
        ]);
        let Resolution::Delegated(cfg) = resolve(&env).unwrap() else {
            panic!("expected Delegated");
        };
        assert_eq!(cfg.coordinator, "https://coord.example");
        assert_eq!(cfg.capability, "deadbeef");
        assert!(cfg.server_cert_sha256.is_none());
    }

    /// The board is inside the token, so a selector alongside it could only
    /// ever disagree — and silently honouring either would make which board you
    /// got depend on a guess.
    #[test]
    fn a_capability_token_refuses_a_selector() {
        for (key, value) in [
            (env::BOARD, "nrf52840dk"),
            (env::ID, "b1"),
            (env::SELECT, "tag=nrf52"),
        ] {
            let env = MapEnv::new(&[
                (env::CAPABILITY, "deadbeef"),
                (env::COORDINATOR, "https://coord.example"),
                (key, value),
            ]);
            assert_eq!(
                resolve(&env),
                Err(SelectorError::CapabilityWithSelector),
                "{key} must not be combinable with a capability"
            );
        }
    }

    /// A sandbox must not be handed a fleet identity by accident: the whole
    /// point of delegation is that it has none.
    #[test]
    fn a_capability_token_refuses_a_session_token() {
        let env = MapEnv::new(&[
            (env::CAPABILITY, "deadbeef"),
            (env::TOKEN, "prfs1_secret"),
            (env::COORDINATOR, "https://coord.example"),
        ]);
        assert_eq!(resolve(&env), Err(SelectorError::CapabilityWithToken));
    }

    #[test]
    fn a_capability_token_still_needs_a_coordinator() {
        let env = MapEnv::new(&[(env::CAPABILITY, "deadbeef")]);
        assert_eq!(resolve(&env), Err(SelectorError::MissingCoordinator));
    }

    #[test]
    fn a_malformed_pin_is_refused_on_the_delegated_path_too() {
        let env = MapEnv::new(&[
            (env::CAPABILITY, "deadbeef"),
            (env::COORDINATOR, "https://coord.example"),
            (env::SERVER_CERT_SHA256, "nope"),
        ]);
        assert_eq!(resolve(&env), Err(SelectorError::InvalidPin));
    }

    /// The lease is decoded from the token locally — no key, no round trip.
    #[test]
    fn the_lease_is_decodable_from_the_capability_token() {
        use fleet_proto::ids::{BoardRef, NodeId, OrgId};
        use fleet_proto::token::{AllowedOp, CapabilityToken, SignedToken};

        let token = CapabilityToken {
            lease: fleet_proto::LeaseId(42),
            board: BoardRef::new(
                OrgId("acme".to_owned()),
                NodeId("rpi-1".to_owned()),
                "nrf52840-dk-3",
            ),
            allowed_ops: vec![AllowedOp::Flash, AllowedOp::Attach],
            expires: 2_000_000_000,
        };
        let signed = SignedToken {
            token_bytes: token.serialize_for_signing().unwrap(),
            // The sidecar never checks the signature: the coordinator does.
            signature: [0u8; fleet_proto::SIGNATURE_LEN],
        };
        let hex = crate::transport::hex_encode(&signed.to_wire());

        let cfg = DelegatedConfig {
            coordinator: "https://coord.example".to_owned(),
            capability: hex,
            server_cert_sha256: None,
        };
        assert_eq!(cfg.lease(), Some(fleet_proto::LeaseId(42)));
    }

    #[test]
    fn an_undecodable_capability_yields_no_lease() {
        for capability in ["", "zz", "abc", "deadbeef"] {
            let cfg = DelegatedConfig {
                coordinator: "https://coord.example".to_owned(),
                capability: capability.to_owned(),
                server_cert_sha256: None,
            };
            assert_eq!(cfg.lease(), None, "{capability} should not decode");
        }
    }
}
