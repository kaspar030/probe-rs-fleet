//! Per-role handlers.
//!
//! Each module owns the arg → config translation for one role and hands off to
//! the owning sibling crate's entry point:
//!
//! - [`coordinator`] → [`fleet_coordinator::run`]
//! - [`agent`] → [`fleet_agent::connection::run`]
//! - [`sidecar`] → [`fleet_sidecar::run`]
//! - [`ctl`] → a thin mTLS client of the coordinator
//!
//! The daemon roles (`coordinator`, `agent`) race their service against
//! [`crate::signal::shutdown`] for graceful termination.

pub mod agent;
pub mod agent_init;
pub mod bootstrap;
pub mod coordinator;
pub mod ctl;
pub mod ctl_init;
pub mod enroll;
pub mod init;
pub mod sidecar;

use anyhow::Result;

/// Print the profiles that exist for `role`, one per line. Used by the
/// `agent profiles` / `ctl profiles` subcommands.
///
/// # Errors
///
/// Returns an error if the XDG config root cannot be resolved.
pub fn list_profiles(role: crate::paths::Role) -> Result<()> {
    let profiles = crate::paths::list_profiles(role)?;
    if profiles.is_empty() {
        println!("(no profiles)");
    } else {
        for profile in profiles {
            println!("{profile}");
        }
    }
    Ok(())
}
