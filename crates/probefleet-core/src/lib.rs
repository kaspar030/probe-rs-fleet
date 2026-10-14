//! Core domain types and shared logic for probe-rs-fleet.
//!
//! This crate is the pure heart of the fleet: domain types plus the
//! deterministic lease [`Scheduler`]. It performs no I/O, no async, and never
//! reads a clock — every time-dependent operation takes `now: u64` (epoch
//! seconds) from the caller. That keeps the scheduling logic fully
//! unit-testable in isolation.
//!
//! The only domain dependency is [`probefleet_proto`]. The coordinator wraps this
//! crate's value objects ([`GrantedLease`], [`ExpiredLease`]) into the wire
//! [`probefleet_proto::LeaseGrant`], minting the signed capability token that is
//! deliberately out of scope here.

pub mod access;
pub mod policy;
pub mod scheduler;

pub use access::{Access, GrantScope};
pub use policy::Policy;
pub use scheduler::{
    ExpireResult, ExpiredLease, GrantedLease, LeaseAuthError, LeaseDecision, Promotion,
    RequesterId, Scheduler,
};
