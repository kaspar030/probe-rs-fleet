//! Sidecar role implementation for probe-rs-fleet.
//!
//! The sidecar runs on developer workstations and CI. It presents a **vanilla
//! `probe-rs` CLI surface** so that `ariel-os` / `laze` invoke it unmodified
//! (see `docs/architecture.md` §4.3). Depending on the environment it either:
//!
//! * **Local fallback** — no fleet selector set ⇒ transparently exec the real
//!   local `probe-rs` (local DX unchanged), or
//! * **Fleet proxy** — a fleet selector is set ⇒ lease a board from the
//!   coordinator, expose a local relay endpoint, point the genuine probe-rs
//!   client at it via `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN`, and let
//!   the real client run against the remote board over the relay.
//!
//! Key insight (investigation #1710): the sidecar **runs the genuine probe-rs
//! client**, it does not re-implement it. The real client does probe + chip
//! selection in-band and computes the exit code, so exit-code propagation is
//! free — the sidecar just propagates the child's exit status.
//!
//! ## Install UX (recommendation)
//!
//! Ship the multi-role `fleet` binary with an **argv0 `probe-rs` symlink on
//! `PATH`** as the primary install story: argv0 dispatch is what lets laze run
//! unmodified. Provide `fleet sidecar run -- <args>` as an explicit escape
//! hatch for debugging. argv0 dispatch wiring lives in `fleet-bin` (task 1714);
//! this crate exposes the reusable [`run`] entry point.
//!
//! ## Module map
//!
//! * [`cli`] — parse the six probe-rs invocation shapes (+ passthrough),
//!   preserving every original argument.
//! * [`selector`] — resolve the fleet configuration from the environment, with
//!   a clean no-selector → local fallback.
//! * [`lease_cache`] — time-based lease sharing keyed by selector + principal.
//! * [`proxy`] — the relay seam (lease / heartbeat / byte-splice). The live
//!   mTLS transport is deferred to tasks 1709 / 1710 / 1711 behind traits.
//! * [`local`] — locate and exec the genuine probe-rs (local + remote env).

pub mod cli;
pub mod lease_cache;
pub mod local;
pub mod proxy;
pub mod selector;

use std::ffi::OsString;

use selector::{EnvSource, Resolution};

/// Errors from the top-level [`run`] entry point.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The argv could not be parsed.
    #[error(transparent)]
    Cli(#[from] cli::CliError),
    /// The fleet selector environment was partial / contradictory.
    #[error(transparent)]
    Selector(#[from] selector::SelectorError),
    /// Locating or running the real probe-rs failed.
    #[error(transparent)]
    Local(#[from] local::LocalError),
    /// The relay / lease transport failed.
    #[error(transparent)]
    Proxy(#[from] proxy::ProxyError),
}

/// Parse `args` (a full process argv) and resolve what the sidecar should do,
/// without performing any side effects. Splitting resolution from execution
/// keeps the decision logic unit-testable.
///
/// Returns the parsed invocation and the environment resolution.
///
/// # Errors
///
/// Returns [`RunError`] if the argv is invalid or the fleet environment is
/// partial / contradictory.
pub fn resolve<I, S>(
    args: I,
    env: &impl EnvSource,
) -> Result<(cli::ProbeRsInvocation, Resolution), RunError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let invocation = cli::parse(tokens)?;
    let resolution = selector::resolve(env)?;
    Ok((invocation, resolution))
}

/// Entry point: parse the probe-rs argv, resolve the environment, and either
/// transparently exec the local probe-rs or proxy the session through the
/// fleet, returning the process exit code to propagate.
///
/// The fleet path is gated on the relay transport (tasks 1709 / 1710 / 1711):
/// until that lands it returns [`proxy::ProxyError::NotYetWired`]. The local
/// fallback path is fully functional today.
///
/// # Errors
///
/// Returns [`RunError`] on a parse error, a partial fleet environment, a
/// failure to locate / run the real probe-rs, or a relay transport error.
pub fn run<I, S>(args: I, env: &impl EnvSource) -> Result<i32, RunError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let tokens: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let invocation = cli::parse(tokens.clone())?;
    let resolution = selector::resolve(env)?;

    match resolution {
        Resolution::Local => {
            // Transparent local fallback: forward the original argv (after
            // argv[0]) to the real probe-rs and propagate its exit code.
            let code = local::exec_local(tokens.into_iter().skip(1))?;
            Ok(code)
        }
        Resolution::Fleet(_cfg) => {
            // The fleet path leases a board, exposes a local relay endpoint,
            // and execs the genuine probe-rs pointed at it. The live transport
            // is deferred behind the proxy seam (tasks 1709/1710/1711).
            let _ = &invocation;
            Err(proxy::ProxyError::NotYetWired.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
    fn resolve_local_when_no_fleet_env() {
        let env = MapEnv::new(&[]);
        let (inv, res) = resolve(
            ["probe-rs", "run", "--chip", "nrf52", "fw.elf"].map(String::from),
            &env,
        )
        .unwrap();
        assert_eq!(inv.chip(), Some("nrf52"));
        assert_eq!(res, Resolution::Local);
    }

    #[test]
    fn resolve_fleet_when_selector_set() {
        let env = MapEnv::new(&[
            (selector::env::BOARD, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let (_inv, res) = resolve(
            ["probe-rs", "run", "--chip", "nrf52", "fw.elf"].map(String::from),
            &env,
        )
        .unwrap();
        assert!(matches!(res, Resolution::Fleet(_)));
    }

    #[test]
    fn run_fleet_path_reports_not_yet_wired() {
        let env = MapEnv::new(&[
            (selector::env::BOARD, "nrf52840-dk-3"),
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run(
            ["probe-rs", "reset", "--chip", "nrf52"].map(String::from),
            &env,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RunError::Proxy(proxy::ProxyError::NotYetWired)
        ));
    }

    #[test]
    fn run_propagates_selector_error() {
        // Coordinator + auth but no board selector → MissingSelector.
        let env = MapEnv::new(&[
            (selector::env::COORDINATOR, "c:4443"),
            (selector::env::TOKEN, "t"),
        ]);
        let err = run(["probe-rs", "reset"].map(String::from), &env).unwrap_err();
        assert!(matches!(
            err,
            RunError::Selector(selector::SelectorError::MissingSelector)
        ));
    }
}
