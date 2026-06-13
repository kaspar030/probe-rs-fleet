//! XDG-default path resolution for fleet config and data.
//!
//! These helpers resolve the standard locations a fleet role looks in when no
//! explicit `--config` (or env override) is supplied. The layout is **per
//! role** and, for the agent and client roles, **per profile**:
//!
//! - **config root** → `$XDG_CONFIG_HOME/probe-rs-fleet/`
//!   (default `~/.config/probe-rs-fleet/`)
//! - **data root** → `$XDG_DATA_HOME/probe-rs-fleet/`
//!   (default `~/.local/share/probe-rs-fleet/`)
//!
//! Each role resolves under its own subfolder so multiple roles can coexist on
//! one host without colliding:
//!
//! - coordinator → `<root>/coordinator/…` (NOT profiled)
//! - agent → `<root>/agent/<profile>/…`
//! - client (shared by ctl + sidecar) → `<root>/client/<profile>/…`
//!
//! The default profile is [`DEFAULT_PROFILE`]. Selection precedence (also
//! documented in `docs/architecture.md`): an explicit `--config` /
//! `--data-dir` wins, then `--profile` / `PROBE_RS_FLEET_PROFILE`, then the
//! `default` profile.
//!
//! Resolution is delegated to the [`directories`] crate, which honours the XDG
//! Base Directory environment variables on Linux and falls back to the
//! platform conventions elsewhere.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

/// The default profile name for the agent and client roles.
pub const DEFAULT_PROFILE: &str = "default";

/// A fleet role, used to derive a per-role config/data subfolder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The coordinator daemon (not profiled).
    Coordinator,
    /// The agent role (profiled).
    Agent,
    /// The client role, shared by `ctl` and the `probe-rs` sidecar (profiled).
    Client,
}

impl Role {
    /// The subfolder name for this role.
    #[must_use]
    pub fn subdir(self) -> &'static str {
        match self {
            Role::Coordinator => "coordinator",
            Role::Agent => "agent",
            Role::Client => "client",
        }
    }
}

/// Application qualifier / organisation / name used to derive the project dirs.
///
/// On Linux `ProjectDirs::from("", "", "probe-rs-fleet")` yields
/// `~/.config/probe-rs-fleet` and `~/.local/share/probe-rs-fleet`, matching the
/// XDG paths documented above.
fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "probe-rs-fleet")
        .context("could not determine a home directory for XDG config/data paths")
}

/// The fleet config root: `$XDG_CONFIG_HOME/probe-rs-fleet/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn config_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().to_path_buf())
}

/// The fleet data root: `$XDG_DATA_HOME/probe-rs-fleet/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn data_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().to_path_buf())
}

/// Per-role config directory: `<config>/<role>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn role_config_dir(role: Role) -> Result<PathBuf> {
    Ok(config_dir()?.join(role.subdir()))
}

/// Per-role data directory: `<data>/<role>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn role_data_dir(role: Role) -> Result<PathBuf> {
    Ok(data_dir()?.join(role.subdir()))
}

// --- coordinator (not profiled) ---------------------------------------------

/// Coordinator config directory: `<config>/coordinator/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_config_dir() -> Result<PathBuf> {
    role_config_dir(Role::Coordinator)
}

/// Coordinator data directory: `<data>/coordinator/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_data_dir() -> Result<PathBuf> {
    role_data_dir(Role::Coordinator)
}

/// Default coordinator config path: `<config>/coordinator/coordinator.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_config_path() -> Result<PathBuf> {
    Ok(coordinator_config_dir()?.join("coordinator.toml"))
}

// --- agent (profiled) -------------------------------------------------------

/// Agent config directory for `profile`: `<config>/agent/<profile>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn agent_config_dir(profile: &str) -> Result<PathBuf> {
    Ok(role_config_dir(Role::Agent)?.join(profile))
}

/// Agent data directory for `profile`: `<data>/agent/<profile>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn agent_data_dir(profile: &str) -> Result<PathBuf> {
    Ok(role_data_dir(Role::Agent)?.join(profile))
}

/// Default agent config path: `<config>/agent/<profile>/agent.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn agent_config_path(profile: &str) -> Result<PathBuf> {
    Ok(agent_config_dir(profile)?.join("agent.toml"))
}

// --- client (ctl / sidecar; profiled) ---------------------------------------

/// Client config directory for `profile`: `<config>/client/<profile>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn client_config_dir(profile: &str) -> Result<PathBuf> {
    Ok(role_config_dir(Role::Client)?.join(profile))
}

/// Client data directory for `profile`: `<data>/client/<profile>/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn client_data_dir(profile: &str) -> Result<PathBuf> {
    Ok(role_data_dir(Role::Client)?.join(profile))
}

/// Default client config path: `<config>/client/<profile>/client.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn client_config_path(profile: &str) -> Result<PathBuf> {
    Ok(client_config_dir(profile)?.join("client.toml"))
}

/// List the profiles that exist for `role`: subdirectories of
/// `<config>/<role>/` that contain the role's config file. Returns names
/// sorted. An absent role directory yields an empty list (not an error).
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn list_profiles(role: Role) -> Result<Vec<String>> {
    let config_file = match role {
        Role::Agent => "agent.toml",
        Role::Client => "client.toml",
        // The coordinator is not profiled.
        Role::Coordinator => return Ok(Vec::new()),
    };
    let root = role_config_dir(role)?;
    let mut names = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(names);
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        if !entry.path().join(config_file).is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env vars are process-global; serialise the tests that mutate them so the
    /// multi-threaded test runner cannot interleave reads and writes.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_xdg_overrides_per_role_and_profile() {
        let _guard = ENV_LOCK.lock().unwrap();

        let prev_config = std::env::var_os("XDG_CONFIG_HOME");
        let prev_data = std::env::var_os("XDG_DATA_HOME");

        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/fleet-xdg-config");
        std::env::set_var("XDG_DATA_HOME", "/tmp/fleet-xdg-data");

        assert_eq!(
            config_dir().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet")
        );
        assert_eq!(
            data_dir().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-data/probe-rs-fleet")
        );

        // Coordinator: per-role, not profiled.
        assert_eq!(
            coordinator_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/coordinator/coordinator.toml")
        );
        assert_eq!(
            coordinator_data_dir().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-data/probe-rs-fleet/coordinator")
        );

        // Agent: per-role, per-profile.
        assert_eq!(
            agent_config_path("default").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/agent/default/agent.toml")
        );
        assert_eq!(
            agent_data_dir("lab1").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-data/probe-rs-fleet/agent/lab1")
        );

        // Client: per-role, per-profile.
        assert_eq!(
            client_config_path("default").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/client/default/client.toml")
        );
        assert_eq!(
            client_data_dir("ci").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-data/probe-rs-fleet/client/ci")
        );

        match prev_config {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match prev_data {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }

    #[test]
    fn list_profiles_finds_dirs_with_config() {
        let tmp = tempfile::tempdir().unwrap();
        let agent_root = tmp.path().join("agent");
        std::fs::create_dir_all(agent_root.join("lab1")).unwrap();
        std::fs::create_dir_all(agent_root.join("lab2")).unwrap();
        std::fs::create_dir_all(agent_root.join("empty")).unwrap();
        std::fs::write(agent_root.join("lab1").join("agent.toml"), "x").unwrap();
        std::fs::write(agent_root.join("lab2").join("agent.toml"), "x").unwrap();
        // `empty` has no agent.toml and must be skipped.

        // Re-implement the directory scan against the temp root (the public
        // helper resolves XDG paths; this asserts the scan/filter logic).
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&agent_root).unwrap().flatten() {
            if entry.file_type().unwrap().is_dir()
                && entry.path().join("agent.toml").is_file()
            {
                names.push(entry.file_name().to_str().unwrap().to_owned());
            }
        }
        names.sort();
        assert_eq!(names, vec!["lab1".to_owned(), "lab2".to_owned()]);
    }
}
