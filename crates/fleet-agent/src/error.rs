//! Agent-wide error type.

use fleet_proto::TokenError;

/// Result alias for agent operations.
pub type Result<T> = std::result::Result<T, AgentError>;

/// Errors produced anywhere in the agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// `boards.toml` / agent-config parsing or validation failed.
    #[error("configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Probe discovery failed.
    #[error("probe discovery failed: {0}")]
    Discovery(String),

    /// A USB-power operation failed.
    #[error("power control error: {0}")]
    Power(#[from] crate::power::PowerError),

    /// Capability-token verification or scope check failed.
    #[error("token error: {0}")]
    Token(#[from] TokenError),

    /// A probe-rs `serve` lifecycle operation failed.
    #[error("probe-rs backend error: {0}")]
    Probers(String),

    /// The control-plane connection failed.
    #[error("connection error: {0}")]
    Connection(String),

    /// An unknown board id was referenced by a coordinator command.
    #[error("unknown board: {0}")]
    UnknownBoard(String),

    /// An I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
