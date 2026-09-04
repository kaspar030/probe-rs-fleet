//! Coordinator role implementation for probe-rs-fleet.
//!
//! The coordinator is the fleet's single publicly reachable, listening node
//! (architecture §4.1). It owns inventory, scheduling/leases (delegated to the
//! pure [`fleet_core::scheduler::Scheduler`]), capability-token auth, the opaque
//! data-plane RELAY, and the audit log. It never touches USB.
//!
//! ## Topology
//!
//! * **Agents** dial *out* and hold one persistent mTLS connection. They send
//!   [`fleet_proto::agent_api::AgentReport`]s up; the coordinator sends
//!   [`fleet_proto::agent_api::CoordinatorCommand`]s back down the same
//!   connection. Agents are pinned by certificate fingerprint.
//! * **Sidecars** connect to request/extend/release leases and to open relay
//!   channels. Their wire protocol ([`proto::SidecarToCoord`] /
//!   [`proto::CoordToSidecar`]) is owned by this crate.
//!
//! ## Data plane
//!
//! When a sidecar opens a channel, the coordinator validates the lease, mints a
//! signed [`fleet_proto::token::CapabilityToken`] (ed25519; see [`auth`]),
//! allocates a [`fleet_proto::ChannelId`], asks the owning agent to open its
//! probe-rs session, then relays opaque [`fleet_proto::DataFrame`]s between the
//! two ends without ever parsing probe-rs traffic.
//!
//! ## Modules
//!
//! The lease/relay/auth decision logic lives in [`core::Coordinator`] and is
//! unit-testable over in-memory channels; [`server`] is the TLS I/O shell and
//! [`sweep`] is the background expiry task.

pub mod auth;
pub mod authz;
pub mod clock;
pub mod config;
pub mod core;
pub mod enroll;
pub mod error;
pub mod proto;
pub mod registry;
pub mod relay;
pub mod server;
pub mod state;
pub mod sweep;

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

pub use crate::auth::Ed25519Signer;
pub use crate::authz::AuthzError;
pub use crate::clock::{now_epoch_secs, Clock, SharedClock, SystemClock};
pub use crate::config::{CoordinatorConfig, SigningKeySource};
pub use crate::core::{Coordinator, SharedCoordinator};
pub use crate::error::{CoordinatorError, Result};
pub use crate::state::{Db, OrgDb};

use fleet_core::scheduler::Scheduler;

/// Build a fully-wired coordinator from its configuration.
///
/// Loads the TLS material, opens the `SQLite` database (running migrations),
/// constructs the signer from the configured key, and seeds the scheduler with
/// the configured policy. Returns the shared coordinator and a ready
/// [`TlsAcceptor`].
///
/// # Errors
///
/// Returns a [`CoordinatorError`] if the config is invalid, TLS material cannot
/// be loaded, or the database cannot be opened/migrated.
pub async fn build(config: CoordinatorConfig) -> Result<(SharedCoordinator, TlsAcceptor)> {
    config.validate()?;

    let cert_chain = fleet_tls::load_cert_chain(&config.tls_cert)?;
    let key = fleet_tls::load_private_key(&config.tls_key)?;
    let client_ca = fleet_tls::load_root_store(&config.client_ca)?;
    let tls_config = fleet_tls::server_config(cert_chain, key, client_ca)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let db = Db::connect(
        config
            .sqlite_path
            .to_str()
            .ok_or_else(|| CoordinatorError::Config("sqlite_path is not UTF-8".to_owned()))?,
    )
    .await?;

    let signer = match &config.signing_key {
        SigningKeySource::Seed(seed) => Ed25519Signer::from_seed(seed),
    };

    let scheduler = Scheduler::new(config.policy.clone());
    let clock: SharedClock = Arc::new(SystemClock);

    let coord = Arc::new(Coordinator::new(config, scheduler, db, signer, clock));
    Ok((coord, acceptor))
}

/// Build and run the coordinator: serve the accept loop and the expiry sweep
/// concurrently until a fatal error.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] if startup fails or the accept loop errors
/// fatally.
pub async fn run(config: CoordinatorConfig) -> Result<()> {
    let (coord, acceptor) = build(config).await?;

    let sweep_handle = {
        let coord = Arc::clone(&coord);
        tokio::spawn(async move { sweep::run(coord).await })
    };

    let result = server::serve(coord, acceptor).await;
    sweep_handle.abort();
    result
}
