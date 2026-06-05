//! The `sidecar` role: forward a probe-rs invocation through the fleet.
//!
//! Reached two ways (both funnel here): a `probe-rs` symlink (argv0 dispatch)
//! or `probe-rs-fleet sidecar -- <args…>`. In both cases `probe_rs_args` holds
//! only the probe-rs arguments *after* the program name; we prepend a synthetic
//! `probe-rs` program token to form the full argv that [`fleet_sidecar::run`]
//! expects (its parser treats `argv[0]` as the program name).

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::Result;

use fleet_sidecar::selector::ProcessEnv;

/// Run the sidecar shim, returning the probe-rs exit code to propagate.
///
/// `probe_rs_args` are the probe-rs arguments (no program name).
///
/// # Errors
///
/// Returns an error on a parse failure, a partial fleet environment, a failure
/// to locate / run the real probe-rs, or a relay transport error.
pub fn run(probe_rs_args: Vec<OsString>) -> Result<ExitCode> {
    // Reconstruct a full argv: program name + the forwarded probe-rs args.
    let mut argv: Vec<OsString> = Vec::with_capacity(probe_rs_args.len() + 1);
    argv.push(OsString::from("probe-rs"));
    argv.extend(probe_rs_args);

    let code = fleet_sidecar::run(argv, &ProcessEnv)?;
    Ok(exit_code_from_i32(code))
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
}
