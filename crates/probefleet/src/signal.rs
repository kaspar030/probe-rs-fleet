//! Graceful-shutdown signal handling for the long-lived daemon roles.
//!
//! Resolves a future that completes on the first of SIGINT (Ctrl-C) or, on
//! Unix, SIGTERM. Daemons `select!` their service against this future to wind
//! down cleanly.
//!
//! The plumbing itself lives in [`probefleet_sidecar::signal::shutdown_signal`],
//! which the sidecar's fleet path needs in order to release its lease on
//! Ctrl-C. This is a thin re-point rather than a second copy, so the two cannot
//! drift; the daemons simply do not care *which* signal fired.

/// Wait for a shutdown signal (Ctrl-C / SIGINT, or SIGTERM on Unix).
///
/// Resolves once any of the watched signals fires. On non-Unix platforms only
/// Ctrl-C is awaited.
pub async fn shutdown() {
    let _signum = probefleet_sidecar::signal::shutdown_signal().await;
}
