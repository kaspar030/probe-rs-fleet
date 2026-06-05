//! Graceful-shutdown signal handling for the long-lived daemon roles.
//!
//! Resolves a future that completes on the first of SIGINT (Ctrl-C) or, on
//! Unix, SIGTERM. Daemons `select!` their service against this future to wind
//! down cleanly.

/// Wait for a shutdown signal (Ctrl-C / SIGINT, or SIGTERM on Unix).
///
/// Resolves once any of the watched signals fires. On non-Unix platforms only
/// Ctrl-C is awaited.
pub async fn shutdown() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
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
            () = ctrl_c => tracing::info!("received SIGINT, shutting down"),
            () = terminate => tracing::info!("received SIGTERM, shutting down"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
        tracing::info!("received Ctrl-C, shutting down");
    }
}
