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
use fleet_proto::AdoptPolicy;

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
    /// How often (seconds) to re-enumerate attached probes.
    ///
    /// Each pass shells out to `probe-rs list`, so it is not free.
    #[serde(default)]
    pub discovery_secs: Option<u64>,
    /// What this node does with a probe `boards.toml` does not declare.
    ///
    /// **Advisory.** The coordinator's `node` row is authoritative for
    /// enforcement; this only governs whether the agent synthesises board
    /// metadata for undeclared probes at all. Editing it here does not change
    /// what the coordinator will adopt — re-run `share` / `agent up --adopt …`.
    ///
    /// Absent means `declared`, the conservative policy: a node whose settings
    /// file predates this key must not silently start offering probes nobody
    /// declared.
    #[serde(default)]
    pub adopt: Option<AdoptPolicy>,
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

impl FleetFileTokenStore {
    /// Apply `edit` to the fleet file's `[node]` table.
    ///
    /// A missing `[node]` table is an **error**, not a no-op. The silent-skip
    /// version of this looks harmless and is not: `rotate_token` acks only if
    /// the persist succeeded, so a no-op would have the node acknowledge a
    /// rotation it never wrote, the coordinator would retire the old token, and
    /// the next restart would load a credential that no longer exists. That is
    /// the same brick the ack-after-persist ordering exists to prevent, reached
    /// from a different direction (a hand-edited or `[node]`-less file).
    fn edit_node(
        &self,
        edit: impl FnOnce(&mut crate::fleet_config::NodeSection),
    ) -> Result<(), String> {
        let mut had_node = false;
        fleet_config::update(&self.path, |f| {
            if let Some(node) = f.node.as_mut() {
                had_node = true;
                edit(node);
            }
        })
        .map_err(|e| format!("{e:#}"))?;
        if had_node {
            Ok(())
        } else {
            Err(format!(
                "{} has no [node] table to write the node token into",
                self.path.display()
            ))
        }
    }
}

impl NodeTokenStore for FleetFileTokenStore {
    fn persist(&self, new_token: &str, previous: Option<&str>) -> Result<(), String> {
        self.edit_node(|node| {
            new_token.clone_into(&mut node.node_token);
            node.previous_node_token = previous.map(ToOwned::to_owned);
        })
    }

    fn commit_current(&self, current: &str) -> Result<(), String> {
        self.edit_node(|node| {
            current.clone_into(&mut node.node_token);
            node.previous_node_token = None;
        })
    }
}

/// Assemble the agent's runtime config from the two sources that hold it.
///
/// Split out from [`run`] so the mapping is testable without a coordinator: this
/// is the function that decides which token the agent dials with after a
/// restart, which is exactly what the lost-ack recovery depends on.
fn assemble_agent_config(
    file: &crate::fleet_config::FleetFile,
    node: &crate::fleet_config::NodeSection,
    settings: &NodeSettings,
    boards_path: PathBuf,
) -> AgentConfig {
    AgentConfig {
        agent_id: node.node_id.clone(),
        fleet_url: file.url.clone(),
        node_token: node.node_token.clone(),
        previous_node_token: node.previous_node_token.clone(),
        server_cert_sha256: file.server_cert_sha256.clone(),
        coordinator_token_pubkey: node.coordinator_token_pubkey.clone(),
        boards_path,
        heartbeat_secs: settings
            .heartbeat_secs
            .unwrap_or_else(fleet_agent::config::default_heartbeat_secs),
        discovery_secs: settings
            .discovery_secs
            .unwrap_or_else(fleet_agent::config::default_discovery_secs),
        adopt: settings.adopt.unwrap_or_default(),
        erase_on_release: settings.erase_on_release,
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
            "loading fleet config {} — register this node with \
             `probe-rs-fleet agent up --fleet {}` (after `login`), or \
             `probe-rs-fleet agent up --fleet {} --fleet-url <url> --auth-key <key>`",
            fleet_path.display(),
            args.fleet,
            args.fleet
        )
    })?;
    let node = file.node.clone().with_context(|| {
        format!(
            "fleet `{}` has no [node] credential on this machine; run \
             `probe-rs-fleet share --fleet {}` (if you have logged in), or \
             `probe-rs-fleet agent up --fleet {} --fleet-url <url> --auth-key <key>`",
            args.fleet, args.fleet, args.fleet
        )
    })?;

    let node_dir = match &args.config_dir {
        Some(dir) => dir.join("node"),
        None => paths::node_config_dir()?,
    };
    let settings = load_node_settings(&node_dir.join("node.toml"))?;
    let boards_path = settings
        .boards_path
        .clone()
        .unwrap_or_else(|| node_dir.join("boards.toml"));

    let agent_config = assemble_agent_config(&file, &node, &settings, boards_path.clone());
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
        adopt = %agent_config.adopt,
        discovery_secs = agent_config.discovery_secs,
        "starting agent"
    );

    // The agent's probe-rs backend spawns `probe-rs` server processes and
    // writes their socket/config files under a per-process runtime directory.
    let runtime_dir =
        std::env::temp_dir().join(format!("probe-rs-fleet-agent-{}", std::process::id()));
    let backend = Arc::new(ProcessBackend::new(runtime_dir));

    let agent =
        Arc::new(Agent::new(agent_config.clone(), boards, backend).context("constructing agent")?);

    // Seed the agent's inventory from `boards.toml` so declared boards are
    // advertised on registration even before the first discovery pass (a node
    // whose probes are all attached behaves identically to before). The
    // connection loop then refines it every `discovery_secs` from a live
    // `probe-rs list`, which is what makes "plug in a board and it becomes
    // leasable" possible under `adopt = "auto"`.
    //
    // The serve-config's canonical `vid:pid:serial` allow entry does NOT depend
    // on either: `ProcessBackend` resolves each board's USB vid/pid from a
    // fresh enumeration at session-open time (see
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

    /// Assemble an `AgentConfig` from a fleet file the way `run` does, which is
    /// what a restart re-does from disk.
    fn agent_config_from(file: &crate::fleet_config::FleetFile) -> AgentConfig {
        assemble_agent_config(
            file,
            file.node.as_ref().expect("[node] table"),
            &NodeSettings::default(),
            PathBuf::from("/boards.toml"),
        )
    }

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

        store.commit_current(&fresh).unwrap();
        let after = fleet_config::load(&path).unwrap();
        assert_eq!(after.node.as_ref().unwrap().node_token, fresh);
        assert!(after.node.as_ref().unwrap().previous_node_token.is_none());
        assert_eq!(after.user.unwrap().session_token, session);
    }

    /// The file-backed half of the lost-ack recovery, including the restart that
    /// is the whole point: after falling back to the pre-rotation token and
    /// connecting with it, a fresh load of the fleet file must yield **that**
    /// token — the one the coordinator accepts — and not the rejected one.
    ///
    /// Before `commit_current` this left the rejected token on disk and dropped
    /// the working one, so the next restart loaded a credential the coordinator
    /// refuses with no fallback left: a headless node recoverable only by
    /// physically visiting it.
    #[test]
    fn a_fallback_survives_a_restart_through_the_fleet_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        fleet_config::update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.node = Some(node_section());
        })
        .unwrap();

        let store = FleetFileTokenStore { path: path.clone() };
        let t1 = fleet_config::load(&path).unwrap().node.unwrap().node_token;
        let t2 = OpaqueToken::mint(TokenKind::Node).to_secret_string();

        // Rotation to T2 is persisted; the ack is then lost, so the coordinator
        // still considers T1 current.
        store.persist(&t2, Some(&t1)).unwrap();

        // The agent restarts, loads T2, is refused, and falls back to T1.
        let mut config = agent_config_from(&fleet_config::load(&path).unwrap());
        assert_eq!(config.node_token, t2);
        assert!(config.fall_back_to_previous_token());
        assert_eq!(config.node_token, t1);

        // The dial with T1 succeeds: commit what worked.
        config.previous_node_token = None;
        store.commit_current(&config.node_token).unwrap();

        // Restart again: the file yields the token that authenticates.
        let reloaded = agent_config_from(&fleet_config::load(&path).unwrap());
        assert_eq!(
            reloaded.node_token, t1,
            "a restart must load the token the coordinator accepts"
        );
        assert!(reloaded.previous_node_token.is_none());
    }

    /// A rotation that cannot be written must FAIL, so `rotate_token` withholds
    /// the ack. Silently no-opping on a `[node]`-less file would have the node
    /// acknowledge a rotation it never stored; the coordinator would retire the
    /// old token and the next restart would find no usable credential at all.
    #[test]
    fn a_write_with_no_node_table_is_an_error_not_a_silent_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("default.toml");
        // A user-only fleet file, as a workstation has.
        fleet_config::update(&path, |f| {
            f.url = "https://fleet.example".to_owned();
            f.user = Some(crate::fleet_config::UserSection {
                session_token: OpaqueToken::mint(TokenKind::Session).to_secret_string(),
                org: "gh-1".to_owned(),
                login: None,
                expires: None,
            });
        })
        .unwrap();

        let store = FleetFileTokenStore { path };
        let fresh = OpaqueToken::mint(TokenKind::Node).to_secret_string();
        assert!(store.persist(&fresh, None).is_err());
        assert!(store.commit_current(&fresh).is_err());
    }
}
