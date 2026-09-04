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
//!
//! Every client role selects its credentials by **fleet name**
//! (`--fleet` / `PROBE_RS_FLEET`), resolving to one file per fleet. See
//! [`crate::fleet_config`].
//!
//! The daemon roles (`coordinator`, `agent`) race their service against
//! [`crate::signal::shutdown`] for graceful termination.

pub mod admin;
pub mod agent;
pub mod agent_init;
pub mod coordinator;
pub mod ctl;
pub mod init;
pub mod login;
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
