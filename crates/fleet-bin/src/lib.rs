//! Single multi-role binary for probe-rs-fleet (library surface).
//!
//! The crate ships a single binary (`probe-rs-fleet`), but it also exposes its
//! modules as a library so integration tests can exercise the role handlers
//! in-process (e.g. the bootstrap-enrollment end-to-end test).

pub mod cli;
pub mod config;
pub mod logging;
pub mod paths;
pub mod roles;
pub mod secrets;
pub mod signal;
