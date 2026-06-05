//! The dial-out control-plane connection (architecture §5).
//!
//! The agent opens **one** persistent mTLS connection *out* to the coordinator
//! and holds it; all coordinator→agent commands travel back down it, so the Pi
//! needs no inbound ports. Over the connection the agent registers, reports
//! inventory, heartbeats, and dispatches [`CoordinatorCommand`]s to the
//! [`Agent`]; the opaque data plane is multiplexed alongside.
//!
//! What ships here: the reconnect-with-backoff policy (unit-tested), the TLS
//! client-config construction via `fleet_tls::client_config`, and the
//! command-dispatch routing. The concrete postcard-rpc topic/endpoint binding
//! is marked `// RESOLVE(1711 wire)` — it is owned jointly with the coordinator
//! task and slots onto the structure here.

use std::sync::Arc;
use std::time::Duration;

use crate::agent::Agent;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::probers::ProbeRsBackend;

use fleet_proto::CoordinatorCommand;

/// Exponential-backoff schedule for reconnect attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    current: Duration,
    max: Duration,
    factor: u32,
}

impl Backoff {
    /// A backoff starting at `initial`, doubling up to `max`.
    #[must_use]
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            current: initial,
            max,
            factor: 2,
        }
    }

    /// The current delay.
    #[must_use]
    pub fn current(&self) -> Duration {
        self.current
    }

    /// Advance the backoff and return the delay to wait before the next try.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * self.factor).min(self.max);
        delay
    }

    /// Reset to the initial delay (call after a successful connection).
    pub fn reset(&mut self, initial: Duration) {
        self.current = initial;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30))
    }
}

/// Build the mTLS [`rustls::ClientConfig`] the agent dials out with.
///
/// Loads the agent's client cert/key and the coordinator-CA trust anchor from
/// the paths in `config`, then delegates to [`fleet_tls::client_config`].
///
/// # Errors
///
/// Returns [`AgentError::Connection`] if any PEM material fails to load or the
/// rustls config is rejected.
pub fn build_client_config(config: &AgentConfig) -> Result<rustls::ClientConfig> {
    let certs = fleet_tls::load_cert_chain(&config.tls_cert)
        .map_err(|e| AgentError::Connection(format!("loading agent cert: {e}")))?;
    let key = fleet_tls::load_private_key(&config.tls_key)
        .map_err(|e| AgentError::Connection(format!("loading agent key: {e}")))?;
    let ca = fleet_tls::load_root_store(&config.tls_ca)
        .map_err(|e| AgentError::Connection(format!("loading coordinator CA: {e}")))?;
    fleet_tls::client_config(certs, key, ca)
        .map_err(|e| AgentError::Connection(format!("building TLS client config: {e}")))
}

/// Routes a decoded [`CoordinatorCommand`] to the agent's handlers.
///
/// Extracted so command dispatch is unit-tested independently of the transport.
///
/// # Errors
///
/// Propagates the agent handler's error.
pub async fn dispatch_command<B: ProbeRsBackend>(
    agent: &Agent<B>,
    cmd: CoordinatorCommand,
) -> Result<()> {
    agent.handle_command(cmd).await
}

/// Run the persistent dial-out connection loop: connect, serve, reconnect with
/// backoff on failure.
///
/// This is the agent's main runtime entrypoint. It owns the lifecycle of one
/// logical connection to the coordinator and restarts it forever (until the
/// process is asked to stop).
///
/// # Errors
///
/// Returns an error only on a non-retryable setup failure (e.g. the TLS config
/// cannot be built). Transient connection failures are retried internally.
pub async fn run<B: ProbeRsBackend + 'static>(
    agent: Arc<Agent<B>>,
    config: AgentConfig,
) -> Result<()> {
    // Validate TLS material up front (non-retryable if misconfigured).
    let _tls = build_client_config(&config)?;
    let mut backoff = Backoff::default();

    loop {
        match connect_and_serve(&agent, &config).await {
            Ok(()) => {
                // Clean disconnect: reset backoff and immediately retry.
                backoff.reset(Duration::from_millis(500));
            }
            Err(e) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %e, retry_in = ?delay, "connection lost; backing off");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// One connection lifetime: dial, register, then serve commands + heartbeats
/// until the connection drops.
///
/// # Errors
///
/// Returns [`AgentError::Connection`] when the connection cannot be established
/// or drops. Currently the live wire is gated pending the coordinator wire
/// binding; see the `RESOLVE(1711 wire)` note.
#[allow(clippy::unused_async)] // real impl awaits the live connection; gated for now
async fn connect_and_serve<B: ProbeRsBackend>(
    agent: &Arc<Agent<B>>,
    config: &AgentConfig,
) -> Result<()> {
    // RESOLVE(1711 wire): establish the TLS stream to
    // `config.coordinator_endpoint`, run the postcard-rpc client that:
    //   1. sends AgentReport::Register { agent, protocol_version },
    //   2. reports the current ProbeInventory,
    //   3. drives a heartbeat on `config.heartbeat_interval()`,
    //   4. subscribes to the ToClient command topic and routes each decoded
    //      `CoordinatorCommand` through `dispatch_command(agent, cmd)`,
    //   5. drains `agent.take_reports()` to the ToServer report topic,
    //   6. multiplexes the opaque data channel (DataFrame) alongside, splicing
    //      each open data channel onto its board's `probe-rs serve` socket and
    //      each open gdb channel onto its `probe-rs gdb` stub via
    //      `crate::gdb::splice` (the gdb-tunnel pump is implemented and tested;
    //      only the live relay wiring is gated here).
    // The topic/endpoint binding is co-owned with task 1711; the structure,
    // handlers, backoff, and TLS config above are complete and tested.
    let _ = (agent, config);
    Err(AgentError::Connection(
        "RESOLVE(1711 wire): postcard-rpc control-plane binding not yet wired".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(800));
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(800));
        // Capped.
        assert_eq!(b.next_delay(), Duration::from_millis(800));
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(10));
        b.next_delay();
        b.next_delay();
        b.reset(Duration::from_millis(100));
        assert_eq!(b.current(), Duration::from_millis(100));
    }

    #[test]
    fn default_backoff_starts_at_500ms() {
        let b = Backoff::default();
        assert_eq!(b.current(), Duration::from_millis(500));
    }
}
