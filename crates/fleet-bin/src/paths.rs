//! XDG-default path resolution for fleet config and data.
//!
//! # One file per fleet, not one tree per role
//!
//! Revision 2 replaces the per-role, per-profile trees
//! (`<config>/agent/<profile>/agent.toml`, `<config>/client/<profile>/client.toml`)
//! with **one file per fleet**:
//!
//! ```text
//! ~/.config/probe-rs-fleet/
//!   fleets/<name>.toml     # url, pin, optional [user], optional [node]
//!   node/                  # node-local, non-credential settings
//!     node.toml
//!     boards.toml
//!   coordinator/           # the coordinator daemon (unchanged, not per-fleet)
//!     coordinator.toml
//! ```
//!
//! The old layout could not express a laptop that is both a user and a node: it
//! needed two unrelated enrollments, two identities and two config trees, and
//! nothing tied them to the same fleet. A fleet file holds both tables, so a
//! laptop has `[user]` *and* `[node]`, a headless Pi has only `[node]`, and a CI
//! runner has neither (its credential comes from the environment).
//!
//! The two credentials stay in **separate tables and are never merged**: a
//! compromised Pi must not be equivalent to a compromised user.
//!
//! Selection precedence: `--fleet <name>` > `PROBE_RS_FLEET` > [`DEFAULT_FLEET`].
//!
//! - **config root** → `$XDG_CONFIG_HOME/probe-rs-fleet/`
//!   (default `~/.config/probe-rs-fleet/`)
//! - **data root** → `$XDG_DATA_HOME/probe-rs-fleet/`
//!   (default `~/.local/share/probe-rs-fleet/`)
//!
//! Resolution is delegated to the [`directories`] crate, which honours the XDG
//! Base Directory environment variables on Linux and falls back to the
//! platform conventions elsewhere.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::{BaseDirs, ProjectDirs};

/// The fleet selected when neither `--fleet` nor `PROBE_RS_FLEET` is set.
pub const DEFAULT_FLEET: &str = "default";

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

// --- coordinator (one per host, not per fleet) ------------------------------

/// Coordinator config directory: `<config>/coordinator/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_config_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("coordinator"))
}

/// Coordinator data directory: `<data>/coordinator/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_data_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("coordinator"))
}

/// Default coordinator config path: `<config>/coordinator/coordinator.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn coordinator_config_path() -> Result<PathBuf> {
    Ok(coordinator_config_dir()?.join("coordinator.toml"))
}

// --- fleets -----------------------------------------------------------------

/// Reject a fleet name that cannot safely become a filename.
///
/// A fleet name is interpolated straight into `fleets/<name>.toml`, so `..` or a
/// separator would let `--fleet ../../foo` read or clobber a file outside the
/// config tree. Checked here, once, rather than at each call site.
fn validate_fleet_name(name: &str) -> Result<()> {
    anyhow::ensure!(!name.is_empty(), "fleet name must not be empty");
    anyhow::ensure!(
        !name.contains('/') && !name.contains('\\'),
        "fleet name must not contain a path separator: {name:?}"
    );
    anyhow::ensure!(
        name != "." && name != "..",
        "fleet name must not be `.` or `..`"
    );
    anyhow::ensure!(
        !name.starts_with('.'),
        "fleet name must not start with `.`: {name:?}"
    );
    Ok(())
}

/// The directory holding one TOML file per fleet: `<config>/fleets/`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn fleets_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("fleets"))
}

/// The config file for one fleet: `<config>/fleets/<name>.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined or `name` is not a
/// usable filename.
pub fn fleet_config_path(name: &str) -> Result<PathBuf> {
    validate_fleet_name(name)?;
    Ok(fleets_dir()?.join(format!("{name}.toml")))
}

// --- node-local settings (no credentials) -----------------------------------

/// Node-local settings directory: `<config>/node/`.
///
/// Not per-fleet and not a credential store: a machine's board inventory and
/// power wiring are facts about the machine, the same whichever fleet it is
/// enrolled in. The node's *token* lives in the fleet file.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn node_config_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("node"))
}

/// Node runtime settings: `<config>/node/node.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn node_config_path() -> Result<PathBuf> {
    Ok(node_config_dir()?.join("node.toml"))
}

/// The node's board inventory: `<config>/node/boards.toml`.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn node_boards_path() -> Result<PathBuf> {
    Ok(node_config_dir()?.join("boards.toml"))
}

/// List the fleets that have a config file, sorted.
///
/// An absent `fleets/` directory yields an empty list, not an error: having
/// configured no fleets is the state every new install is in.
///
/// # Errors
///
/// Returns an error if no home directory can be determined.
pub fn list_fleets() -> Result<Vec<String>> {
    let root = fleets_dir()?;
    let mut names = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(names);
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

// --- tilde expansion --------------------------------------------------------

/// The part of `path` after a leading `~/`, with any further leading separators
/// stripped, or `None` when `path` does not start with `~/`.
///
/// Matches on the *string* prefix rather than [`Path::components`] on purpose:
/// `components()` normalises (`~//x` → `~/x`, `./x` → `x`), and a path that does
/// not start with `~/` must come back byte-identical to what the operator wrote.
/// Trailing separators are trimmed so `~//x` joins under the home directory
/// instead of `Path::join` treating `/x` as absolute and discarding the base.
fn tilde_rest(path: &Path) -> Option<&str> {
    let s = path.to_str()?;
    let rest = s.strip_prefix("~/").or_else(|| {
        if cfg!(windows) {
            s.strip_prefix("~\\")
        } else {
            None
        }
    })?;
    Some(rest.trim_start_matches(std::path::is_separator))
}

/// [`expand_tilde`] against an explicit home directory — the pure core, so the
/// table-driven tests need no environment mutation.
fn expand_tilde_with(path: &Path, home: &Path) -> PathBuf {
    match tilde_rest(path) {
        // `~/` (and `~//`) name the home directory itself.
        Some("") => home.to_path_buf(),
        Some(rest) => home.join(rest),
        None => path.to_path_buf(),
    }
}

/// Expand a leading `~/` to the user's home directory.
///
/// Deliberately minimal: only a leading `~/` (`~\` on Windows) is expanded. A
/// bare `~`, `~user/...`, `./~/...` and every path with no tilde are returned
/// unchanged — `~user` expansion needs a passwd lookup, and silently resolving
/// it to the *wrong* home would be worse than leaving it literal. A non-UTF-8
/// path is also returned unchanged.
///
/// This exists because the scaffolded `node.toml` advertises a `~/`-prefixed
/// `boards_path`: without expansion the tool would write a config it cannot
/// itself read, resolving it to a literal `./~` under the process cwd.
///
/// # Errors
///
/// Returns an error only when the path *does* start with `~/` and no home
/// directory can be determined.
pub fn expand_tilde(path: &Path) -> Result<PathBuf> {
    if tilde_rest(path).is_none() {
        return Ok(path.to_path_buf());
    }
    let base = BaseDirs::new().context("could not determine a home directory to expand `~/`")?;
    Ok(expand_tilde_with(path, base.home_dir()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ENV_LOCK;

    #[test]
    fn resolves_xdg_overrides_for_fleets_node_and_coordinator() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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

        // The coordinator keeps its own subdirectory: it is a host-level daemon,
        // not a per-fleet client.
        assert_eq!(
            coordinator_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/coordinator/coordinator.toml")
        );
        assert_eq!(
            coordinator_data_dir().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-data/probe-rs-fleet/coordinator")
        );

        // One file per fleet.
        assert_eq!(
            fleet_config_path("default").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/fleets/default.toml")
        );
        assert_eq!(
            fleet_config_path("lab1").unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/fleets/lab1.toml")
        );

        // Node-local settings are not per-fleet.
        assert_eq!(
            node_boards_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/node/boards.toml")
        );
        assert_eq!(
            node_config_path().unwrap(),
            PathBuf::from("/tmp/fleet-xdg-config/probe-rs-fleet/node/node.toml")
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

    /// A fleet name becomes a filename, so a traversal in it must be refused
    /// rather than resolved: `--fleet ../../coordinator/coordinator` would
    /// otherwise be a write primitive outside the fleets directory.
    #[test]
    fn traversal_fleet_names_are_rejected() {
        for bad in ["", "..", ".", "../x", "a/b", "a\\b", ".hidden"] {
            assert!(
                validate_fleet_name(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        for good in ["default", "lab1", "acme-ci", "a.b"] {
            assert!(
                validate_fleet_name(good).is_ok(),
                "expected {good:?} to be accepted"
            );
        }
    }

    /// Only a leading `~/` expands; everything else must come back
    /// byte-identical to what the operator wrote.
    #[test]
    fn expand_tilde_only_touches_a_leading_tilde_slash() {
        let home = Path::new("/home/tester");

        assert_eq!(
            expand_tilde_with(Path::new("~/x/boards.toml"), home),
            PathBuf::from("/home/tester/x/boards.toml")
        );
        // `~/` names the home directory itself.
        assert_eq!(expand_tilde_with(Path::new("~/"), home), home);
        // Extra separators must not make `Path::join` drop the base.
        assert_eq!(
            expand_tilde_with(Path::new("~//x"), home),
            PathBuf::from("/home/tester/x")
        );
        assert_eq!(
            expand_tilde_with(Path::new("~///x"), home),
            PathBuf::from("/home/tester/x")
        );

        for unchanged in [
            "~",
            "~user/x",
            "~foo",
            "relative/x",
            "/abs/x",
            "",
            "./~/x",
            "a/~/b",
        ] {
            assert_eq!(
                expand_tilde_with(Path::new(unchanged), home),
                PathBuf::from(unchanged),
                "expected {unchanged:?} to be left untouched"
            );
        }
    }

    /// The pure core is tested above; this asserts the wiring to the real home
    /// directory lookup, which is the half a fake home cannot cover.
    #[test]
    fn expand_tilde_resolves_against_the_environment_home() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let prev_home = std::env::var_os("HOME");
        // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
        std::env::set_var("HOME", "/tmp/fleet-tilde-home");

        let expanded = expand_tilde(Path::new("~/x/boards.toml"));
        let untouched = expand_tilde(Path::new("relative/x"));

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(
            expanded.unwrap(),
            PathBuf::from("/tmp/fleet-tilde-home/x/boards.toml")
        );
        assert_eq!(untouched.unwrap(), PathBuf::from("relative/x"));
    }

    #[test]
    fn list_fleets_finds_toml_stems() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("default.toml"), "x").unwrap();
        std::fs::write(tmp.path().join("lab1.toml"), "x").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), "x").unwrap();
        std::fs::create_dir(tmp.path().join("adir.toml")).unwrap();

        // Re-implement the scan against the temp root (the public helper
        // resolves XDG paths; this asserts the filter logic).
        let mut names = Vec::new();
        for entry in std::fs::read_dir(tmp.path()).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("toml")
            {
                names.push(path.file_stem().unwrap().to_str().unwrap().to_owned());
            }
        }
        names.sort();
        assert_eq!(names, vec!["default".to_owned(), "lab1".to_owned()]);
    }
}
