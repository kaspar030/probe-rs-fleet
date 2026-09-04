//! The `agent` role: dial out to the coordinator and drive local probes.
//!
//! # Where the agent's configuration comes from now
//!
//! `agent.toml` is gone. The agent assembles its runtime config from two
//! sources with different lifetimes and different sensitivity:
//!
//! * the selected **fleet file**'s `[node]` table — the credential, the node id
//!   and the coordinator's token-signing pubkey (0600);
//! * `~/.config/probe-rs-fleet/node/node.toml` — the machine's own settings
//!   (boards path, heartbeat, erase-on-release), which are true of the machine
//!   whichever fleet it belongs to.
//!
//! Splitting them is what makes a laptop that is *also* a user expressible: the
//! credential lives beside the user's session token in one per-fleet file, the
//! machine facts do not have to be duplicated per fleet.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

use fleet_agent::agent::Agent;
use fleet_agent::config::{AgentConfig, BoardsConfig, NodeTokenStore};
use fleet_agent::connection;
use fleet_agent::probers::ProcessBackend;

use crate::cli::AgentArgs;
use crate::fleet_config;
use crate::paths;

/// The on-disk shape of `node/node.toml`: node-local, non-credential settings.
///
/// Every field has a default, so an absent file is equivalent to an empty one —
/// a node that has nothing to say about itself should not have to say it.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeSettings {
    /// Path to this node's `boards.toml`. Defaults to `node/boards.toml`.
    #[serde(default)]
    pub boards_path: Option<PathBuf>,
    /// Heartbeat interval, seconds.
    #[serde(default)]
    pub heartbeat_secs: Option<u64>,
    /// Whether to erase the target's flash on lease release.
    #[serde(default)]
    pub erase_on_release: bool,
}

/// Load `node/node.toml`, treating an absent file as all-defaults.
///
/// # Errors
///
/// Returns an error only if the file exists and is malformed: silently ignoring
/// a typo'd setting is how a node quietly stops erasing flash between leases.
pub fn load_node_settings(path: &std::path::Path) -> Result<NodeSettings> {
    if !path.exists() {
        return Ok(NodeSettings::default());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading node settings {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing node settings {}", path.display()))
}

/// Persists a rotated node token into the fleet file's `[node]` table.
///
/// Read-modify-write on every call (see [`crate::fleet_config`]): a rotation
/// must not clobber the `[user]` table a concurrent `login` wrote, and vice
/// versa. The window between read and rename is a lost update, recoverable by
/// re-running the losing command — whereas a whole-file rewrite would silently
/// destroy the other credential.
struct FleetFileTokenStore {
    path: PathBuf,
}

impl NodeTokenStore for FleetFileTokenStore {
    fn persist(&self, new_token: &str, previous: Option<&str>) -> Result<(), String> {
        fleet_config::update(&self.path, |f| {
            if let Some(node) = f.node.as_mut() {
                new_token.clone_into(&mut node.node_token);
                node.previous_node_token = previous.map(ToOwned::to_owned);
            }
        })
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
    }

    fn clear_previous(&self) -> Result<(), String> {
        fleet_config::update(&self.path, |f| {
            if let Some(node) = f.node.as_mut() {
                node.previous_node_token = None;
            }
        })
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
    }
}

/// Load the agent's configuration, build the agent, and run its persistent
/// dial-out connection loop until a shutdown signal or a fatal setup error.
///
/// # Errors
///
/// Returns an error if the fleet has no `[node]` credential, either config file
/// cannot be loaded, the agent cannot be constructed, or the connection loop
/// fails with a non-retryable error.
pub async fn run(args: AgentArgs) -> Result<()> {
    let fleet_path = match &args.config_dir {
        Some(dir) => dir.join(format!("{}.toml", args.fleet)),
        None => paths::fleet_config_path(&args.fleet)?,
    };
    let file = fleet_config::load(&fleet_path).with_context(|| {
        format!(
            "loading fleet config {} — enroll this node with \
             `probe-rs-fleet agent init --fleet {} --fleet-url <url> --auth-key <key>`",
            fleet_path.display(),
            args.fleet
        )
    })?;
    let node = file.node.clone().with_context(|| {
        format!(
            "fleet `{}` has no [node] credential on this machine; run \
             `probe-rs-fleet agent init --fleet {} --fleet-url <url> --auth-key <key>`",
            args.fleet, args.fleet
        )
    })?;

    let node_dir = match &args.config_dir {
        Some(dir) => dir.join("node"),
        None => paths::node_config_dir()?,
    };
    let settings = load_node_settings(&node_dir.join("node.toml"))?;
    let boards_path = settings
        .boards_path
        .unwrap_or_else(|| node_dir.join("boards.toml"));

    let agent_config = AgentConfig {
        agent_id: node.node_id.clone(),
        fleet_url: file.url.clone(),
        node_token: node.node_token.clone(),
        previous_node_token: node.previous_node_token.clone(),
        server_cert_sha256: file.server_cert_sha256.clone(),
        coordinator_token_pubkey: node.coordinator_token_pubkey.clone(),
        boards_path: boards_path.clone(),
        heartbeat_secs: settings
            .heartbeat_secs
            .unwrap_or_else(fleet_agent::config::default_heartbeat_secs),
        erase_on_release: settings.erase_on_release,
    };
    agent_config
        .validate()
        .context("validating the assembled agent configuration")?;

    let boards = BoardsConfig::from_path(&boards_path)
        .with_context(|| format!("loading boards.toml {}", boards_path.display()))?;

    tracing::info!(
        agent_id = %agent_config.agent_id,
        coordinator = %agent_config.fleet_url,
        fleet = %args.fleet,
        boards = boards.boards.len(),
        "starting agent"
    );

    // The agent's probe-rs backend spawns `probe-rs` server processes and
    // writes their socket/config files under a per-process runtime directory.
    let runtime_dir =
        std::env::temp_dir().join(format!("probe-rs-fleet-agent-{}", std::process::id()));
    let backend = Arc::new(ProcessBackend::new(runtime_dir));

    let agent =
        Arc::new(Agent::new(agent_config.clone(), boards, backend).context("constructing agent")?);

    // Seed the agent's inventory from `boards.toml` so the boards are advertised
    // to the coordinator on registration and become leasable. (A concrete probe
    // enumerator can later refine presence via `Agent::set_inventory`.) The
    // serve-config's canonical `vid:pid:serial` allow entry does NOT depend on
    // this: `ProcessBackend` resolves each board's USB vid/pid from a live
    // `probe-rs list` enumeration at session-open time (see
    // `ProcessBackend::serve_spec`).
    agent.seed_inventory_from_boards().await;

    let store: Arc<dyn NodeTokenStore> = Arc::new(FleetFileTokenStore { path: fleet_path });

    // `connection::run` owns the connect / serve / reconnect-with-backoff
    // lifecycle (task 1712); race it against shutdown for clean termination.
    tokio::select! {
        result = connection::run(agent, agent_config, store) => {
            result.context("agent connection loop exited with an error")?;
            tracing::info!("agent stopped");
        }
        () = crate::signal::shutdown() => {
            tracing::info!("agent shutting down");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};

    fn node_section() -> crate::fleet_config::NodeSection {
        crate::fleet_config::NodeSection {
            node_token: OpaqueToken::mint(TokenKind::Node).to_secret_string(),
            node_id: "gh-1/pi".to_owned(),
            coordinator_token_pubkey: "ab".repeat(32),
            previous_node_token: None,
        }
    }

    #[test]
    fn absent_node_settings_are_all_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let s = load_node_settings(&tmp.path().join("node.toml")).unwrap();
        assert!(s.boards_path.is_none());
        assert!(s.heartbeat_secs.is_none());
        assert!(!s.erase_on_release);
    }

    /// A malformed `node.toml` must fail loudly: quietly falling back to
    /// defaults would, for instance, silently stop erasing flash between leases.
    #[test]
    fn a_malformed_node_settings_file_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.toml");
        std::fs::write(&path, "heartbeat_secs = \"not a number\"").unwrap();
        assert!(load_node_settings(&path).is_err());
    }

    #[test]
    fn node_settings_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.toml");
        std::fs::write(
            &path,
            "boards_path = \"/etc/fleet/boards.toml\"\nheartbeat_secs = 30\nerase_on_release = true\n",
        )
        .unwrap();
        let s = load_node_settings(&path).unwrap();
        assert_eq!(
            s.boards_path.unwrap(),
            PathBuf::from("/etc/fleet/boards.toml")
        );
        assert_eq!(s.heartbeat_secs, Some(30));
        assert!(s.erase_on_release);
    }

    /// Rotation is read-modify-write, so a `[user]` credential sharing the file
    /// survives it. On a laptop the alternative is silently logging the human
    /// out every time the coordinator rotates the node token.
    #[test]
    fn the_token_store_rotates_node_without_touching_user() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        let session = OpaqueToken::mint(TokenKind::Session).to_secret_string();
        fleet_config::update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.node = Some(node_section());
            f.user = Some(crate::fleet_config::UserSection {
                session_token: session.clone(),
                org: "gh-1".to_owned(),
                login: None,
                expires: None,
            });
        })
        .unwrap();
        let original = fleet_config::load(&path).unwrap().node.unwrap().node_token;

        let store = FleetFileTokenStore { path: path.clone() };
        let fresh = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        store.persist(&fresh, Some(&original)).unwrap();

        let after = fleet_config::load(&path).unwrap();
        assert_eq!(after.node.as_ref().unwrap().node_token, fresh);
        assert_eq!(
            after.node.as_ref().unwrap().previous_node_token.as_deref(),
            Some(original.as_str())
        );
        assert_eq!(after.user.as_ref().unwrap().session_token, session);

        store.clear_previous().unwrap();
        let after = fleet_config::load(&path).unwrap();
        assert!(after.node.as_ref().unwrap().previous_node_token.is_none());
        assert_eq!(after.user.unwrap().session_token, session);
    }
}
