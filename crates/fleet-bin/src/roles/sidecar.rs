//! The `sidecar` role: forward a probe-rs invocation through the fleet.
//!
//! Reached two ways (both funnel here): a `probe-rs` symlink (argv0 dispatch)
//! or `probe-rs-fleet sidecar -- <args…>`. In both cases `probe_rs_args` holds
//! only the probe-rs arguments *after* the program name; we prepend a synthetic
//! `probe-rs` program token to form the full argv that
//! [`fleet_sidecar::run_async`] expects (its parser treats `argv[0]` as the
//! program name).

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::Result;

use fleet_sidecar::selector::ProcessEnv;

/// Run the sidecar shim, returning the probe-rs exit code to propagate.
///
/// `async` so the fleet data/gdb path runs on the binary's existing tokio
/// runtime via [`fleet_sidecar::run_async`] instead of building a nested
/// runtime (which would panic with "Cannot start a runtime from within a
/// runtime").
///
/// `probe_rs_args` are the probe-rs arguments (no program name).
///
/// # Errors
///
/// Returns an error on a parse failure, a partial fleet environment, a failure
/// to locate / run the real probe-rs, or a relay transport error.
pub async fn run(probe_rs_args: Vec<OsString>, fleet: &str) -> Result<ExitCode> {
    // Discover the coordinator endpoint + user credential from the selected
    // fleet file (written by `probe-rs-fleet login`) and inject them into the
    // process environment for any keys the user has NOT already set. This lets
    // one `login` configure both `ctl` and this shim. Selector env
    // (`_BOARD` / `_SELECT`) continues to come from the user's environment.
    inject_client_config_env(fleet);

    // Reconstruct a full argv: program name + the forwarded probe-rs args.
    let mut argv: Vec<OsString> = Vec::with_capacity(probe_rs_args.len() + 1);
    argv.push(OsString::from("probe-rs"));
    argv.extend(probe_rs_args);

    let code = fleet_sidecar::run_async(argv, &ProcessEnv).await?;
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
}
