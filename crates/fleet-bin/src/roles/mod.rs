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
pub mod coordinator;
pub mod ctl;
pub mod ctl_init;
pub mod enroll;
pub mod init;
pub mod sidecar;
