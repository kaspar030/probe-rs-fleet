//! Coordinator role implementation for probe-rs-fleet.
//!
//! The coordinator is the fleet's single publicly reachable, listening node
//! (architecture §4.1). It owns inventory, scheduling/leases (delegated to the
//! pure [`fleet_core::scheduler::Scheduler`]), capability-token auth, the opaque
//! data-plane RELAY, and the audit log. It never touches USB.
//!
//! ## Topology
//!
//! Since revision 2 (§3.5) the coordinator is an **HTTP server**: `GET /agent`
//! and `GET /client` upgrade to `WebSocket`s, `POST /auth/token` exchanges
//! credentials, `GET /healthz` answers the proxy. Every principal presents
//! `Authorization: Bearer …` on the upgrade; there are no client certificates.
//!
//! * **Agents** dial *out* and hold one persistent `WebSocket`. They send
//!   [`fleet_proto::agent_api::AgentReport`]s up; the coordinator sends
//!   [`fleet_proto::agent_api::CoordinatorCommand`]s back down the same
//!   connection. A node is identified by the `node` row its token hash matched.
//! * **Sidecars and `ctl`** connect to request/extend/release leases and to open
//!   relay channels ([`proto::SidecarToCoord`] / [`proto::CoordToSidecar`]).
//!
//! ## Deployment
//!
//! The expected deployment is **behind an HTTPS reverse proxy**: the proxy
//! terminates TLS and the coordinator speaks plain HTTP on loopback. That is
//! what the `WebSocket` transport buys — a proxy can route it, which it could
//! not do for the bespoke length-prefixed TCP protocol this replaced.
//! [`config::TlsConfig`] keeps the self-hosted option of terminating TLS here.
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
//! unit-testable over in-memory channels; [`http`] is the route surface,
//! [`server`] the per-connection I/O shell, and [`sweep`] the background expiry
//! task. The browser surface (`docs/web-ui.md`) is split off rather than grown
//! into `http`: [`browser_auth`] holds the cookie/CSRF machinery and the two
//! login flows, [`api`] the `/api/v1` JSON handlers.

pub mod api;
pub mod auth;
pub mod authz;
pub mod browser_auth;
pub mod clock;
pub mod config;
pub mod core;
pub mod error;
pub mod http;
pub mod proto;
pub mod registry;
pub mod relay;
pub mod server;
pub mod state;
pub mod sweep;
pub mod tokens;
pub mod ws_axum;

use std::sync::Arc;

use tracing::info;

pub use crate::auth::Ed25519Signer;
pub use crate::authz::AuthzError;
pub use crate::clock::{now_epoch_secs, Clock, SharedClock, SystemClock};
pub use crate::config::{CoordinatorConfig, SigningKeySource, TlsConfig};
pub use crate::core::{Coordinator, SharedCoordinator};
pub use crate::error::{CoordinatorError, Result};
pub use crate::state::{Db, OrgDb};

use fleet_core::scheduler::Scheduler;

/// Build a fully-wired coordinator from its configuration.
///
/// Opens the `SQLite` database (running migrations), constructs the signer from
/// the configured key, and seeds the scheduler with the configured policy.
///
/// Note there is no TLS material to load here any more: the client half is gone
/// with the private CA, and the optional server half is loaded by [`run`] only
/// if a `[tls]` table is configured.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] if the config is invalid or the database
/// cannot be opened/migrated.
pub async fn build(config: CoordinatorConfig) -> Result<SharedCoordinator> {
    config.validate()?;

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

    Ok(Arc::new(Coordinator::new(
        config, scheduler, db, signer, clock,
    )))
}

/// Build and run the coordinator: serve HTTP and the expiry sweep concurrently
/// until a fatal error.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] if startup fails or the listener errors
/// fatally.
pub async fn run(config: CoordinatorConfig) -> Result<()> {
    let tls = config.tls.clone();
    let listen_addr = config.listen_addr;
    let coord = build(config).await?;

    let sweep_handle = {
        let coord = Arc::clone(&coord);
        tokio::spawn(async move { sweep::run(coord).await })
    };

    let router = http::router(Arc::clone(&coord));
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let local = listener.local_addr()?;

    let result = match tls {
        None => {
            info!(addr = %local, "coordinator listening (plain HTTP; TLS is the proxy's job)");
            // `into_make_service_with_connect_info` is what populates the peer
            // address `/node/register/start` records for an approver to look
            // at. A serve path without it degrades to `source_ip = NULL`
            // rather than failing — see the `Option<Extension<ConnectInfo<..>>>`
            // extractor there.
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .map_err(|e| CoordinatorError::Http(e.to_string()))
        }
        Some(tls) => {
            info!(addr = %local, "coordinator listening (TLS terminated here)");
            serve_tls(listener, router, &tls).await
        }
    };

    sweep_handle.abort();
    result
}

/// Serve the router over coordinator-terminated TLS.
///
/// **Not** `axum::serve`: that path cannot carry `WebSocket` upgrades over a
/// manual TLS accept loop. Upgrades need
/// `hyper_util::server::conn::auto::Builder::serve_connection_with_upgrades`,
/// and getting this wrong produces a coordinator whose `/agent` route 400s only
/// when `[tls]` is configured — which is exactly the configuration that is
/// hardest to test by accident.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] if the TLS material cannot be loaded. Per
/// connection failures are logged and do not stop the loop.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    tls: &TlsConfig,
) -> Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;

    let chain = fleet_tls::load_cert_chain(&tls.cert)?;
    let key = fleet_tls::load_private_key(&tls.key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(fleet_tls::server_config(chain, key)?));

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        // Not `into_make_service_with_connect_info`: that is a `MakeService`
        // adapter for `axum::serve`, and this path deliberately does not use
        // `axum::serve` (see the doc comment above — WS upgrades need
        // `serve_connection_with_upgrades`). The peer is already bound here, so
        // it is injected per connection instead, giving handlers the same
        // `Extension<ConnectInfo<..>>` the plain path produces.
        let service = TowerToHyperService::new(
            router
                .clone()
                .layer(axum::Extension(axum::extract::ConnectInfo(peer))),
        );
        tokio::spawn(async move {
            let stream = match acceptor.accept(sock).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
            };
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%peer, error = %e, "connection closed");
            }
        });
    }
}
