//! The `sidecar` role: forward a probe-rs invocation through the fleet.
//!
//! Reached two ways (both funnel here): a `probe-rs` symlink (argv0 dispatch)
//! or `probe-rs-fleet sidecar -- <args…>`. In both cases `probe_rs_args` holds
//! only the probe-rs arguments *after* the program name; we prepend a synthetic
//! `probe-rs` program token to form the full argv that
//! [`fleet_sidecar::run_async`] expects (its parser treats `argv[0]` as the
//! program name).
//!
//! # Selecting the board
//!
//! The board selector normally comes from the environment
//! (`PROBE_RS_FLEET_BOARD` / `_SELECT`), which is what laze and CI use. The
//! explicit subcommand additionally accepts `--board <ID>` / `--select <EXPR>`;
//! a flag **beats** the environment and replaces *both* selector variables (see
//! [`SelectorFlags`]). The argv0 `probe-rs` path has no flags — it forwards
//! every argument verbatim to stay transparent to laze — so there the
//! environment remains the only mechanism.

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::{Context, Result};

use fleet_sidecar::selector::{env, EnvSource, ProcessEnv};

/// The sidecar's CLI selector flags: `--board` / `--select`.
///
/// Clap makes the two mutually exclusive, so at most one is ever set. An empty
/// string is normalised to `None` at construction: `--select ''` is a typo, not
/// a request to select nothing, and letting it through would mask the
/// environment and fail later with the less helpful `MissingSelector`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectorFlags {
    board: Option<String>,
    select: Option<String>,
}

impl SelectorFlags {
    /// Build from the parsed flags, dropping empty values.
    #[must_use]
    pub fn new(board: Option<String>, select: Option<String>) -> Self {
        let non_empty = |s: Option<String>| s.filter(|v| !v.is_empty());
        Self {
            board: non_empty(board),
            select: non_empty(select),
        }
    }

    /// Whether any flag was given (and so overrides the environment).
    fn is_set(&self) -> bool {
        self.board.is_some() || self.select.is_some()
    }

    /// Validate a `--select` expression eagerly, so a typo names the *flag*.
    ///
    /// [`fleet_sidecar::selector::resolve`] would reject it too, but its error
    /// talks about `PROBE_RS_FLEET_SELECT`, which is confusing when the value
    /// came from the command line.
    fn validate(&self) -> Result<()> {
        if let Some(expr) = &self.select {
            fleet_proto::lease::parse_constraint(expr, fleet_proto::lease::BareTerm::Tag)
                .with_context(|| format!("invalid --select {expr:?}"))?;
        }
        Ok(())
    }

    /// Layer these flags over an [`EnvSource`].
    fn over<E: EnvSource>(self, inner: E) -> SelectorOverride<E> {
        SelectorOverride { inner, flags: self }
    }
}

/// A CLI selector flag layered over an [`EnvSource`].
///
/// An explicit flag beats the environment, and *replaces both* selector
/// variables rather than adding a second one — so `--select` alongside a stale
/// `PROBE_RS_FLEET_BOARD` is not `AmbiguousSelector`, it is just the flag.
/// Every other key (including `PROBE_RS_FLEET_CAPABILITY`) falls through
/// untouched, so `resolve` still refuses a selector next to a capability token
/// (`CapabilityWithSelector`): the board is inside the token.
///
/// An overlay rather than `std::env::set_var` deliberately: no process-global
/// mutation, so the tests stay pure and the flag does not leak into the
/// probe-rs child process's environment.
struct SelectorOverride<E> {
    inner: E,
    flags: SelectorFlags,
}

impl<E: EnvSource> EnvSource for SelectorOverride<E> {
    fn get(&self, key: &str) -> Option<String> {
        if self.flags.is_set() {
            match key {
                env::BOARD => return self.flags.board.clone(),
                env::SELECT => return self.flags.select.clone(),
                _ => {}
            }
        }
        self.inner.get(key)
    }
}

/// Run the sidecar shim, returning the probe-rs exit code to propagate.
///
/// `async` so the fleet data/gdb path runs on the binary's existing tokio
/// runtime via [`fleet_sidecar::run_async`] instead of building a nested
/// runtime (which would panic with "Cannot start a runtime from within a
/// runtime").
///
/// `probe_rs_args` are the probe-rs arguments (no program name); `flags` are
/// the CLI selector flags (empty on the argv0 path).
///
/// # Errors
///
/// Returns an error on a parse failure, an invalid `--select` expression, a
/// partial fleet environment, a failure to locate / run the real probe-rs, or a
/// relay transport error.
pub async fn run(
    probe_rs_args: Vec<OsString>,
    fleet: &str,
    flags: SelectorFlags,
) -> Result<ExitCode> {
    flags.validate()?;

    // Discover the coordinator endpoint + user credential from the selected
    // fleet file (written by `probe-rs-fleet login`) and inject them into the
    // process environment for any keys the user has NOT already set. This lets
    // one `login` configure both `ctl` and this shim.
    //
    // Credentials keep that precedence deliberately (env > file). The board
    // *selector* is the other way round: it defaults to the environment
    // (`_BOARD` / `_SELECT`), but an explicit `--board` / `--select` flag wins
    // — an argument typed on this command line is more specific than an
    // exported variable. The flag is layered on with `SelectorOverride` rather
    // than written into the environment.
    inject_client_config_env(fleet);

    // Reconstruct a full argv: program name + the forwarded probe-rs args.
    let mut argv: Vec<OsString> = Vec::with_capacity(probe_rs_args.len() + 1);
    argv.push(OsString::from("probe-rs"));
    argv.extend(probe_rs_args);

    let code = fleet_sidecar::run_async(argv, &flags.over(ProcessEnv)).await?;
    Ok(exit_code_from_i32(code))
}

/// Populate the sidecar's coordinator / credential env vars from the fleet file
/// for any key not already present in the environment.
///
/// Only the `[user]` table is consulted: the shim runs a probe-rs invocation on
/// the human's behalf, and a machine that is also a node must not silently
/// present its *node* credential here. That is the whole reason the two tokens
/// stay separate.
///
/// No refresh happens on this path. The shim is a short-lived child process of
/// a build or test run, and blocking it on an HTTP round trip — or worse,
/// racing a concurrent `ctl` for the one refreshable token — is not worth the
/// few minutes it would buy; an expired token surfaces as an auth error telling
/// the user to run `login`.
fn inject_client_config_env(fleet: &str) {
    let Some(file) = crate::fleet_config::load_named_opt(fleet) else {
        return;
    };
    let Some(user) = file.user.as_ref() else {
        return;
    };

    set_env_if_absent("PROBE_RS_FLEET_COORDINATOR", &file.url);
    set_env_if_absent("PROBE_RS_FLEET_TOKEN", &user.session_token);
    if let Some(pin) = &file.server_cert_sha256 {
        set_env_if_absent("PROBE_RS_FLEET_SERVER_CERT_SHA256", pin);
    }
}

/// Set an env var only if it is not already present (and non-empty).
fn set_env_if_absent(key: &str, value: &str) {
    let already = std::env::var_os(key).is_some_and(|v| !v.is_empty());
    if !already {
        // SAFETY of correctness (not memory): although an outer tokio runtime
        // now exists, this env injection runs synchronously at the very top of
        // the sidecar role — before the first `.await` and before any sidecar
        // code reads these vars — so no other task or thread is reading the
        // environment concurrently.
        std::env::set_var(key, value);
    }
}

/// Convert a probe-rs process exit code into an [`ExitCode`].
///
/// `ExitCode::from` takes a `u8`; codes outside `0..=255` (or negative,
/// signalling a signal-termination on Unix) collapse to a generic failure.
fn exit_code_from_i32(code: i32) -> ExitCode {
    match u8::try_from(code) {
        Ok(c) => ExitCode::from(c),
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_zero_to_success_byte() {
        // ExitCode has no Eq; compare via the documented byte conversion path.
        assert!(matches!(u8::try_from(0), Ok(0)));
        let _ = exit_code_from_i32(0);
    }

    #[test]
    fn out_of_range_codes_collapse_to_failure() {
        // 256 and negative codes are not representable as a u8 exit byte.
        assert!(u8::try_from(256_i32).is_err());
        assert!(u8::try_from(-1_i32).is_err());
        let _ = exit_code_from_i32(256);
        let _ = exit_code_from_i32(-1);
    }

    #[test]
    fn set_env_if_absent_respects_existing_value() {
        let key = "PROBE_RS_FLEET_TEST_INJECT_EXISTING";
        // SAFETY of correctness: a unique key only this test touches.
        std::env::set_var(key, "user-set");
        set_env_if_absent(key, "injected");
        assert_eq!(std::env::var(key).unwrap(), "user-set");
        std::env::remove_var(key);
    }

    #[test]
    fn set_env_if_absent_sets_when_unset() {
        let key = "PROBE_RS_FLEET_TEST_INJECT_UNSET";
        std::env::remove_var(key);
        set_env_if_absent(key, "injected");
        assert_eq!(std::env::var(key).unwrap(), "injected");
        std::env::remove_var(key);
    }

    // --- selector flags ----------------------------------------------------
    //
    // Pure overlay tests: no process-env mutation, so these are parallel-safe.

    use fleet_proto::ids::BoardName;
    use fleet_proto::lease::Constraint;
    use fleet_sidecar::selector::{resolve, Resolution, SelectorError};

    /// A closure-backed [`EnvSource`] over a fixed key/value list.
    fn map_env(pairs: &'static [(&'static str, &'static str)]) -> impl EnvSource {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    /// A credential environment with `PROBE_RS_FLEET_SELECT` set, so `resolve`
    /// gets past the coordinator / token checks and down to the selector.
    const ENV_WITH_SELECT: [(&str, &str); 3] = [
        (env::COORDINATOR, "https://fleet.example"),
        (env::TOKEN, "tok"),
        (env::SELECT, "tag=from-env"),
    ];

    fn constraint_of(res: Resolution) -> Constraint {
        match res {
            Resolution::Fleet(cfg) => cfg.select,
            other => panic!("expected Fleet, got {other:?}"),
        }
    }

    fn tags(t: &str) -> Constraint {
        Constraint::Tags(vec![t.to_owned()])
    }

    #[test]
    fn no_flags_is_transparent() {
        let overlay = SelectorFlags::default().over(map_env(&ENV_WITH_SELECT));
        assert_eq!(
            overlay.get(env::COORDINATOR).as_deref(),
            Some("https://fleet.example")
        );
        assert_eq!(constraint_of(resolve(&overlay).unwrap()), tags("from-env"));
    }

    #[test]
    fn select_flag_beats_select_env() {
        let flags = SelectorFlags::new(None, Some("tag=from-flag".to_owned()));
        let overlay = flags.over(map_env(&ENV_WITH_SELECT));
        assert_eq!(constraint_of(resolve(&overlay).unwrap()), tags("from-flag"));
    }

    #[test]
    fn select_flag_replaces_board_env_rather_than_clashing() {
        // The point of replacing *both* selector vars: no AmbiguousSelector.
        const ENV_WITH_BOARD: [(&str, &str); 3] = [
            (env::COORDINATOR, "https://fleet.example"),
            (env::TOKEN, "tok"),
            (env::BOARD, "nrf52840-dk-9"),
        ];
        let flags = SelectorFlags::new(None, Some("tag=from-flag".to_owned()));
        let overlay = flags.over(map_env(&ENV_WITH_BOARD));
        assert_eq!(overlay.get(env::BOARD), None);
        assert_eq!(constraint_of(resolve(&overlay).unwrap()), tags("from-flag"));
    }

    #[test]
    fn board_flag_replaces_select_env() {
        let flags = SelectorFlags::new(Some("nrf52840-dk-1".to_owned()), None);
        let overlay = flags.over(map_env(&ENV_WITH_SELECT));
        assert_eq!(overlay.get(env::SELECT), None);
        assert_eq!(
            constraint_of(resolve(&overlay).unwrap()),
            Constraint::Board(BoardName("nrf52840-dk-1".to_owned()))
        );
    }

    #[test]
    fn capability_plus_flag_is_still_refused() {
        const ENV_CAP: [(&str, &str); 2] = [
            (env::COORDINATOR, "https://fleet.example"),
            (env::CAPABILITY, "deadbeef"),
        ];
        let flags = SelectorFlags::new(None, Some("tag=from-flag".to_owned()));
        assert!(matches!(
            resolve(&flags.over(map_env(&ENV_CAP))),
            Err(SelectorError::CapabilityWithSelector)
        ));
    }

    #[test]
    fn non_selector_keys_always_fall_through() {
        const ENV_ALL: [(&str, &str); 3] = [
            (env::COORDINATOR, "https://fleet.example"),
            (env::TOKEN, "tok"),
            (env::CAPABILITY, "cap"),
        ];
        let overlay = SelectorFlags::new(Some("b".to_owned()), None).over(map_env(&ENV_ALL));
        assert_eq!(overlay.get(env::TOKEN).as_deref(), Some("tok"));
        assert_eq!(overlay.get(env::CAPABILITY).as_deref(), Some("cap"));
        assert_eq!(
            overlay.get(env::COORDINATOR).as_deref(),
            Some("https://fleet.example")
        );
    }

    #[test]
    fn empty_flag_value_is_ignored_and_env_still_applies() {
        let flags = SelectorFlags::new(None, Some(String::new()));
        assert_eq!(flags, SelectorFlags::default());
        let overlay = flags.over(map_env(&ENV_WITH_SELECT));
        assert_eq!(constraint_of(resolve(&overlay).unwrap()), tags("from-env"));
    }

    #[test]
    fn invalid_select_expression_names_the_flag() {
        let err = SelectorFlags::new(None, Some("chip=a && tag=b".to_owned()))
            .validate()
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--select"), "{msg}");
        assert!(!msg.contains("PROBE_RS_FLEET_SELECT"), "{msg}");
    }

    #[test]
    fn valid_select_expression_passes_validation() {
        let expr = SelectorFlags::new(None, Some("tag=nrf52 && bluetooth".to_owned()));
        assert!(expr.validate().is_ok());
        let board = SelectorFlags::new(Some("nrf52840-dk-1".to_owned()), None);
        assert!(board.validate().is_ok());
    }
}
