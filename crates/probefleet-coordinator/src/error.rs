//! Error type for the coordinator.

use probefleet_proto::ids::{LeaseId, NodeId};

/// Errors produced by the coordinator's runtime and helpers.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    /// A TLS-layer failure (config build or handshake).
    #[error("tls error: {0}")]
    Tls(#[from] probefleet_tls::TlsError),

    /// A transport-layer failure on a `WebSocket` connection.
    ///
    /// Kept distinct from [`CoordinatorError::Io`] so a benign peer close can
    /// be recognised (see [`CoordinatorError::as_wire`]) and logged as the
    /// normal end of a short-lived `ctl` session rather than as a fault.
    #[error("wire error: {0}")]
    Wire(probefleet_wire::WireError),

    /// An HTTP-layer failure (listener, upgrade, or serving).
    /// A forgs storage failure (users, orgs, credentials, grants).
    #[error("identity store error: {0}")]
    Store(#[from] forgs_store::StoreError),

    /// The auth surface could not be configured.
    #[error("auth configuration error: {0}")]
    AuthConfig(#[from] forgs_http::ConfigError),

    #[error("http error: {0}")]
    Http(String),

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
    Token(#[from] probefleet_proto::token::TokenError),

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

    /// The owning node for a board is not currently connected.
    #[error("node {0} is not connected")]
    NodeUnavailable(NodeId),

    /// The referenced lease is not known to the scheduler.
    #[error("lease {0:?} not found")]
    LeaseNotFound(LeaseId),

    /// A configuration value was invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// A persisted value is not one this build understands.
    ///
    /// Distinct from [`CoordinatorError::Db`]: the query succeeded, the *data*
    /// is unrecognised. Kept loud rather than defaulted, because the one thing
    /// stored here — a node's `adopt_policy` — decides whether an undeclared
    /// probe is adopted, and guessing would adopt probes nobody shared.
    #[error("invalid persisted state: {0}")]
    State(String),
}

impl CoordinatorError {
    /// View this error as a [`probefleet_wire::WireError`], for benign-close
    /// classification.
    ///
    /// `ctl` runs one request and exits, so a peer close is the expected end of
    /// such a connection. Without this, every `ctl list` would log a transport
    /// warning on the coordinator.
    #[must_use]
    pub fn as_wire(&self) -> probefleet_wire::WireError {
        match self {
            CoordinatorError::Wire(w) => match w {
                probefleet_wire::WireError::Closed => probefleet_wire::WireError::Closed,
                probefleet_wire::WireError::Protocol(m) => {
                    probefleet_wire::WireError::Protocol(m.clone())
                }
                probefleet_wire::WireError::Io(io) => {
                    probefleet_wire::WireError::Io(std::io::Error::new(io.kind(), io.to_string()))
                }
            },
            CoordinatorError::Io(io) => {
                probefleet_wire::WireError::Io(std::io::Error::new(io.kind(), io.to_string()))
            }
            other => probefleet_wire::WireError::Protocol(other.to_string()),
        }
    }
}

/// Convenience result alias for coordinator operations.
pub type Result<T> = std::result::Result<T, CoordinatorError>;
