//! Per-role handlers.
//!
//! Each module owns the arg → config translation for one role and hands off to
//! the owning sibling crate's entry point:
//!
//! - [`coordinator`] → [`fleet_coordinator::run`]
//! - [`agent`] → [`fleet_agent::connection::run`]
//! - [`sidecar`] → [`fleet_sidecar::run`]
//! - [`ctl`] → a caller of `fleet_sidecar::transport::CoordSession`, the one
//!   coordinator client the tree has
//! - [`login`] → the GitHub device flow, brokered by the coordinator
//! - [`share`] → self-register this machine as a node with the login it has
//! - [`auth_key`] → mint/list/revoke this org's auth keys with that same login
//! - [`node_approve`] → approve a headless machine that printed a short code
//! - [`agent_up`] → the §4.2 credential ladder, then [`agent`]
//! - [`node_setup`] → the enrollment mechanics [`share`] and [`agent_up`] share
//!
//! Every client role selects its credentials by **fleet name**
//! (`--fleet` / `PROBE_RS_FLEET`), resolving to one file per fleet. See
//! [`crate::fleet_config`].
//!
//! The daemon roles (`coordinator`, `agent`) race their service against
//! [`crate::signal::shutdown`] for graceful termination.

pub mod admin;
pub mod agent;
pub mod agent_up;
pub mod auth_key;
pub mod coordinator;
pub mod ctl;
pub mod init;
pub mod login;
pub mod node_approve;
pub mod node_setup;
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
