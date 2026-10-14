//! Per-role handlers.
//!
//! Each module owns the arg → config translation for one role and hands off to
//! the owning sibling crate's entry point:
//!
//! - [`coordinator`] → [`probefleet_coordinator::run`]
//! - [`node_run`] → [`probefleet_agent::connection::run`]
//! - [`sidecar`] → [`probefleet_sidecar::run`]
//! - [`ctl`] → a caller of `probefleet_sidecar::transport::CoordSession`, the one
//!   coordinator client the tree has
//! - [`login`] → the coordinator's (forgs) device flow, any login provider
//! - [`logout`] → revoke this machine's session and refresh token (`--all`:
//!   every one the caller holds, the lost-machine answer)
//! - [`share`] → self-register this machine as a node with the login it has
//! - [`auth_key`] → mint/list/revoke this org's auth keys with that same login
//! - [`org`] → create team orgs and manage their members with that same login
//! - [`grant`] → share a subset of this org's boards with another person
//! - [`ci`] → exchange a CI job's workload identity for a per-job fleet token
//! - [`agent_login`] → store a durable auth key so a persistent sandbox holds a
//!   self-renewing session instead of an hourly `ci login` wrapper
//! - [`completions`] → print how to switch shell completion on
//! - [`node_approve`] → approve a headless machine that printed a short code
//! - [`node_board`] → declare a board (discover probes, append to
//!   `boards.toml`) instead of hand-editing it
//! - [`node_up`] → the §4.2 credential ladder, then [`node_run`]
//! - [`node_setup`] → the enrollment mechanics [`share`] and [`node_up`] share
//!
//! Every client role selects its credentials by **fleet name**
//! (`--fleet` / `PROBE_RS_FLEET`), resolving to one file per fleet. See
//! [`crate::fleet_config`].
//!
//! The daemon roles (`coordinator`, `node_run`) race their service against
//! [`crate::signal::shutdown`] for graceful termination.

pub mod admin;
pub mod agent_login;
pub mod auth_key;
pub mod ci;
pub mod completions;
pub mod coordinator;
pub mod ctl;
pub mod grant;
pub mod init;
pub mod login;
pub mod logout;
pub mod node_approve;
pub mod node_board;
pub mod node_run;
pub mod node_setup;
pub mod node_up;
pub mod org;
pub mod share;
pub mod sidecar;

use anyhow::Result;

/// Print the fleets this machine has a config for, one per line. Backs
/// `probe-rs-fleet fleets`.
///
/// # Errors
///
/// Returns an error if the XDG config root cannot be resolved.
pub fn list_fleets() -> Result<()> {
    let fleets = crate::paths::list_fleets()?;
    if fleets.is_empty() {
        println!("(no fleets configured — run `probe-rs-fleet login --fleet-url <url>`)");
    } else {
        for fleet in fleets {
            println!("{fleet}");
        }
    }
    Ok(())
}
