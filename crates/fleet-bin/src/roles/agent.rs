//! The `agent` role: dial out to the coordinator and drive local probes.

use std::sync::Arc;

use anyhow::{Context, Result};

use fleet_agent::agent::Agent;
use fleet_agent::config::{AgentConfig, BoardsConfig};
use fleet_agent::connection;
use fleet_agent::probers::ProcessBackend;

use crate::cli::AgentArgs;
use crate::paths;

/// Load the agent + boards config, build the agent, and run its persistent
/// dial-out connection loop until a shutdown signal or a fatal setup error.
///
/// # Errors
///
/// Returns an error if either config file cannot be loaded, the agent cannot be
/// constructed, or the connection loop fails with a non-retryable error.
pub async fn run(args: AgentArgs) -> Result<()> {
    let config_path = match args.config {
        Some(path) => path,
        None => paths::agent_config_path(&args.profile)?,
    };
    let agent_config = AgentConfig::from_path(&config_path)
        .with_context(|| format!("loading agent config {}", config_path.display()))?;
    let boards = BoardsConfig::from_path(&agent_config.boards_path)
        .with_context(|| format!("loading boards.toml {}", agent_config.boards_path))?;

    tracing::info!(
        agent_id = %agent_config.agent_id,
        coordinator = %agent_config.coordinator_endpoint,
        boards = boards.boards.len(),
        "starting agent"
    );

    // The agent's probe-rs backend spawns `probe-rs` server processes and
    // writes their socket/config files under a per-process runtime directory.
    let runtime_dir = std::env::temp_dir().join(format!("probe-rs-fleet-agent-{}", std::process::id()));
    let backend = Arc::new(ProcessBackend::new(runtime_dir));

    let agent = Arc::new(
        Agent::new(agent_config.clone(), boards, backend)
            .context("constructing agent")?,
    );

    // `connection::run` owns the connect / serve / reconnect-with-backoff
    // lifecycle (task 1712); race it against shutdown for clean termination.
    tokio::select! {
        result = connection::run(agent, agent_config) => {
            result.context("agent connection loop exited with an error")?;
            tracing::info!("agent stopped");
        }
        () = crate::signal::shutdown() => {
            tracing::info!("agent shutting down");
        }
    }

    Ok(())
}
