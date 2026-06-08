//! XDG-default path resolution for fleet config and data.
//!
//! These helpers resolve the standard locations a fleet role looks in when no
//! explicit `--config` (or env override) is supplied:
//!
//! - **config dir** → `$XDG_CONFIG_HOME/probe-rs-fleet/`
//!   (default `~/.config/probe-rs-fleet/`)
//! - **data dir** → `$XDG_DATA_HOME/probe-rs-fleet/`
//!   (default `~/.local/share/probe-rs-fleet/`)
//!
//! Resolution is delegated to the [`directories`] crate, which honours the XDG
//! Base Directory environment variables on Linux and falls back to the
//! platform conventions elsewhere.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

/// Application qualifier / organisation / name used to derive the project dirs.
///
/// On Linux `ProjectDirs::from("", "", "probe-rs-fleet")` yields
/// `~/.config/probe-rs-fleet` and `~/.local/share/probe-rs-fleet`, matching the
/// XDG paths documented above.
fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "probe-rs-fleet")
        .context("could not determine a home directory for XDG config/data paths")
}

/// The fleet config directory: `$XDG_CONFIG_HOME/probe-rs-fleet/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn config_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().to_path_buf())
}

/// The fleet data directory: `$XDG_DATA_HOME/probe-rs-fleet/`.
///
/// This is the default home for generated cert/key/seed material and the
/// coordinator's `SQLite` database.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn data_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().to_path_buf())
}

/// Default coordinator config path:
/// `$XDG_CONFIG_HOME/probe-rs-fleet/coordinator.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("coordinator.toml"))
}

/// Default agent config path:
/// `$XDG_CONFIG_HOME/probe-rs-fleet/agent.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn agent_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("agent.toml"))
}

/// Default client (ctl / sidecar) config path:
/// `$XDG_CONFIG_HOME/probe-rs-fleet/client.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn client_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("client.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env vars are process-global; serialise the tests that mutate them so the
    /// multi-threaded test runner cannot interleave reads and writes.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_xdg_overrides() {
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
        assert_eq!(
            coordinator_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/coordinator.toml")
        );
        assert_eq!(
            agent_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/agent.toml")
        );
        assert_eq!(
            client_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/client.toml")
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
}
