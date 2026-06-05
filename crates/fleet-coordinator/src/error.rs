//! Error type for the coordinator.

use fleet_proto::ids::{AgentId, LeaseId};

/// Errors produced by the coordinator's runtime and helpers.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    /// A TLS-layer failure (config build or handshake).
    #[error("tls error: {0}")]
    Tls(#[from] fleet_tls::TlsError),

    /// Failed to derive a peer identity from its certificate.
    #[error("identity error: {0}")]
    Identity(#[from] fleet_tls::IdentityError),

    /// An I/O failure on a socket or file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A database failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// A database migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A capability-token signing/encoding failure.
    #[error("token error: {0}")]
    Token(#[from] fleet_proto::token::TokenError),

    /// A frame could not be encoded or decoded.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The peer's protocol version did not match ours.
    #[error("protocol version mismatch: peer={peer} ours={ours}")]
    VersionMismatch {
        /// The version the peer announced.
        peer: u32,
        /// The version this coordinator speaks.
        ours: u32,
    },

    /// The owning agent for a board is not currently connected.
    #[error("agent {0} is not connected")]
    AgentUnavailable(AgentId),

    /// The referenced lease is not known to the scheduler.
    #[error("lease {0:?} not found")]
    LeaseNotFound(LeaseId),

    /// A configuration value was invalid.
    #[error("configuration error: {0}")]
    Config(String),
}

/// Convenience result alias for coordinator operations.
pub type Result<T> = std::result::Result<T, CoordinatorError>;
