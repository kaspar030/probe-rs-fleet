//! Single multi-role binary for probe-rs-fleet (library surface).
//!
//! The crate ships a single binary (`probe-rs-fleet`), but it also exposes its
//! modules as a library so integration tests can exercise the role handlers
//! in-process (e.g. the bootstrap-enrollment end-to-end test).

pub mod cli;
pub mod config;
pub mod logging;
pub mod paths;
pub mod roles;
pub mod secrets;
pub mod signal;

/// Test-only support shared across modules.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    /// Process-wide lock for tests that mutate global env vars (`XDG_*_HOME`,
    /// `HOME`, …). All such tests across the crate compile into one binary and
    /// run multithreaded, so they must serialise on this single shared lock —
    /// per-module locks would not mutually exclude.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
}
