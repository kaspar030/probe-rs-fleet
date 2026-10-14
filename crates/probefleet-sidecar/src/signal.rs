//! Shutdown-signal handling for the sidecar's fleet path.
//!
//! A sidecar holds an exclusive lease for the life of one probe-rs invocation.
//! If it dies without releasing, the board stays leased until the lease TTL
//! expires — which is why the fleet path `select!`s its work against
//! [`shutdown_signal`] and releases on the way out. This covers SIGINT (Ctrl-C,
//! the common case: a user aborting `probe-rs run`) and SIGTERM. Nothing can
//! cover SIGKILL; that case is bounded by the lease TTL instead, which is why
//! the sidecar no longer requests a hardcoded hour.
//!
//! `probefleet`'s daemon roles use the same plumbing through
//! `probefleet::signal::shutdown`, which delegates here so the two cannot drift.

/// Wait for a shutdown signal, returning the signal number that fired.
///
/// Resolves on the first of SIGINT (2) or, on Unix, SIGTERM (15). On non-Unix
/// platforms only Ctrl-C is awaited and 2 is reported. The number is returned
/// so the caller can propagate the conventional `128 + signum` exit code, which
/// is exactly what a signalled child process would have produced.
///
/// If a handler cannot be installed the error is logged and that arm parks
/// forever rather than resolving spuriously: a phantom "signal" would release a
/// live lease out from under a running flash.
pub async fn shutdown_signal() -> i32 {
    /// SIGINT.
    const SIGINT: i32 = 2;
    #[cfg(unix)]
    /// SIGTERM.
    const SIGTERM: i32 = 15;

    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(error) => {
                    tracing::error!(%error, "failed to install SIGTERM handler");
                    // Park forever so the `select!` falls through to Ctrl-C.
                    std::future::pending::<()>().await;
                }
            }
        };

        tokio::select! {
            () = ctrl_c => {
                tracing::info!("received SIGINT, shutting down");
                SIGINT
            }
            () = terminate => {
                tracing::info!("received SIGTERM, shutting down");
                SIGTERM
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
        tracing::info!("received Ctrl-C, shutting down");
        SIGINT
    }
}
