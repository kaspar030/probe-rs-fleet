//! The `coordinator` role: run the fleet coordinator daemon.

use anyhow::{Context, Result};

use crate::cli::CoordinatorArgs;
use crate::config;

/// Load the coordinator config and run the daemon until a shutdown signal or a
/// fatal error.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or the coordinator exits
/// with a fatal error.
pub async fn run(args: CoordinatorArgs) -> Result<()> {
    let cfg = config::load_coordinator_config(&args.config)
        .with_context(|| format!("loading coordinator config {}", args.config.display()))?;

    tracing::info!(listen = %cfg.listen_addr, "starting coordinator");

    // Race the coordinator's accept/sweep loop against a shutdown signal so
    // SIGINT/SIGTERM tear it down cleanly. `fleet_coordinator::run` owns the
    // serve + expiry-sweep lifecycle (task 1711).
    tokio::select! {
        result = fleet_coordinator::run(cfg) => {
            result.context("coordinator exited with an error")?;
            tracing::info!("coordinator stopped");
        }
        () = crate::signal::shutdown() => {
            tracing::info!("coordinator shutting down");
        }
    }

    Ok(())
}
