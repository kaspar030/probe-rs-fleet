//! Tracing initialisation shared by all roles.
//!
//! Builds a `tracing-subscriber` `fmt` layer driven by `RUST_LOG`
//! (via [`EnvFilter`]), defaulting to `info` when unset. All diagnostic
//! output goes to **stderr** so that stdout stays clean for the sidecar's
//! forwarded probe-rs output and exit-code fidelity (architecture §4.3 / §7).

use tracing_subscriber::EnvFilter;

/// Initialise the global tracing subscriber for the process.
///
/// Idempotent in spirit: it uses `try_init` and silently ignores the error if
/// a subscriber is already installed (e.g. in tests).
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
