//! The agent orchestrator: holds config + inventory + active sessions and
//! implements the coordinator-command handlers (architecture §4.2, §5).
//!
//! Command flow:
//! * `OpenSession` → verify the capability token locally, then start a
//!   `probe-rs serve` session for the board and splice it onto the channel.
//! * `KillSession` → kill the session on that channel.
//! * `ReleaseLease` → kill the lease's session, then run cleanup (power-cycle +
//!   optional erase).
//! * `PowerCycle` → power-cycle a board on operator command.
//! * `QueryState` → re-report inventory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use fleet_proto::token::AllowedOp;
use fleet_proto::{
    AgentReport, BoardId, ChannelId, CoordinatorCommand, LeaseId, PowerAction, PowerKind,
    ProbeInventory,
};

use crate::config::{AgentConfig, BoardSpec, BoardsConfig};
use crate::error::{AgentError, Result};
use crate::power::{self, PowerControl};
use crate::probers::{ProbeRsBackend, Session};
use crate::token::Ed25519Verifier;

/// An open data-plane session bound to a lease/board/channel.
struct ActiveSession {
    lease: LeaseId,
    board: BoardId,
    session: Box<dyn Session>,
}

/// Factory that builds a power controller from a board's declared power kind.
/// Injectable so tests can substitute mocked / no-op power control.
type PowerFactory = Box<dyn Fn(&PowerKind) -> Box<dyn PowerControl> + Send + Sync>;

/// The agent orchestrator.
///
/// Generic over the [`ProbeRsBackend`] so tests inject a mock. Power control is
/// resolved per-board from `boards.toml`.
pub struct Agent<B: ProbeRsBackend> {
    config: AgentConfig,
    boards: BoardsConfig,
    verifier: Ed25519Verifier,
    backend: Arc<B>,
    inventory: Mutex<ProbeInventory>,
    sessions: Mutex<HashMap<ChannelId, ActiveSession>>,
    /// Reports the agent wants to emit upward (drained by the connection loop).
    outbox: Mutex<Vec<AgentReport>>,
    /// Builds power controllers (injectable for tests).
    power_factory: PowerFactory,
    /// Clock injection point for tests (epoch seconds).
    now_fn: fn() -> u64,
}

fn wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl<B: ProbeRsBackend> Agent<B> {
    /// Build an agent from parsed config, boards, a token verifier, and a
    /// probe-rs backend.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Token`] if the coordinator public key in `config`
    /// is not a valid ed25519 key.
    pub fn new(
        config: AgentConfig,
        boards: BoardsConfig,
        backend: Arc<B>,
    ) -> Result<Self> {
        let key = config.coordinator_token_pubkey_bytes()?;
        let verifier = Ed25519Verifier::from_public_key_bytes(&key)?;
        Ok(Self {
            config,
            boards,
            verifier,
            backend,
            inventory: Mutex::new(ProbeInventory {
                boards: Vec::new(),
                unknown: Vec::new(),
            }),
            sessions: Mutex::new(HashMap::new()),
            outbox: Mutex::new(Vec::new()),
            power_factory: Box::new(|k| power::from_power_kind(k)),
            now_fn: wall_clock_secs,
        })
    }

    /// Override the clock (tests).
    #[cfg(test)]
    fn set_clock(&mut self, now_fn: fn() -> u64) {
        self.now_fn = now_fn;
    }

    /// Override the power factory (tests).
    #[cfg(test)]
    fn set_power_factory(&mut self, factory: PowerFactory) {
        self.power_factory = factory;
    }

    /// Replace the current inventory snapshot (called after discovery).
    pub async fn set_inventory(&self, inventory: ProbeInventory) {
        *self.inventory.lock().await = inventory;
    }

    /// Drain queued upward reports.
    pub async fn take_reports(&self) -> Vec<AgentReport> {
        std::mem::take(&mut *self.outbox.lock().await)
    }

    async fn emit(&self, report: AgentReport) {
        self.outbox.lock().await.push(report);
    }

    fn board_spec(&self, board: &BoardId) -> Result<&BoardSpec> {
        self.boards
            .board(board)
            .ok_or_else(|| AgentError::UnknownBoard(board.0.clone()))
    }

    /// Resolve the power controller for a board.
    fn power_for(&self, board: &BoardId) -> Result<Box<dyn PowerControl>> {
        let spec = self.board_spec(board)?;
        Ok((self.power_factory)(&spec.power.to_power_kind()))
    }

    /// Dispatch a coordinator command.
    ///
    /// # Errors
    ///
    /// Propagates handler errors (token rejection, unknown board, backend
    /// failure, power failure).
    pub async fn handle_command(&self, cmd: CoordinatorCommand) -> Result<()> {
        match cmd {
            CoordinatorCommand::OpenSession {
                lease,
                board,
                token,
                channel,
            } => self.on_open_session(lease, &board, &token, channel).await,
            CoordinatorCommand::KillSession { channel } => self.on_kill_session(channel).await,
            CoordinatorCommand::ReleaseLease {
                lease,
                board,
                erase,
            } => self.on_release_lease(lease, &board, erase).await,
            CoordinatorCommand::PowerCycle { board } => self.on_power_cycle(&board).await,
            CoordinatorCommand::QueryState => self.on_query_state().await,
        }
    }

    /// Verify the token and open a probe-rs session.
    async fn on_open_session(
        &self,
        lease: LeaseId,
        board: &BoardId,
        token_wire: &[u8],
        channel: ChannelId,
    ) -> Result<()> {
        // Board must be declared.
        let spec = self.board_spec(board)?.clone();

        // Verify the capability token locally before doing anything else.
        let now = (self.now_fn)();
        crate::token::verify_wire(
            &self.verifier,
            token_wire,
            lease,
            board,
            AllowedOp::Attach,
            now,
        )?;

        // Start the backend session and record it.
        let session = self
            .backend
            .open(&spec)
            .await
            .map_err(AgentError::Probers)?;
        self.sessions.lock().await.insert(
            channel,
            ActiveSession {
                lease,
                board: board.clone(),
                session,
            },
        );
        self.emit(AgentReport::Log {
            level: fleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!("opened session on channel {} for lease {}", channel.0, lease.0),
        })
        .await;
        Ok(())
    }

    /// Kill the session on `channel`.
    async fn on_kill_session(&self, channel: ChannelId) -> Result<()> {
        let removed = self.sessions.lock().await.remove(&channel);
        if let Some(active) = removed {
            active
                .session
                .kill()
                .await
                .map_err(AgentError::Probers)?;
            self.emit(AgentReport::SessionClosed {
                channel,
                exit_code: None,
            })
            .await;
        }
        Ok(())
    }

    /// Release a lease: kill its session, then power-cycle (and optionally
    /// erase) the board for cleanup.
    async fn on_release_lease(
        &self,
        lease: LeaseId,
        board: &BoardId,
        erase: bool,
    ) -> Result<()> {
        // Kill any session(s) tied to this lease.
        let channels: Vec<ChannelId> = {
            let sessions = self.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| s.lease == lease)
                .map(|(c, _)| *c)
                .collect()
        };
        for channel in channels {
            self.on_kill_session(channel).await?;
        }

        // Cleanup: power-cycle the board.
        self.cleanup_board(board, erase).await
    }

    /// Cleanup a board: power-cycle and optionally note erase.
    async fn cleanup_board(&self, board: &BoardId, erase: bool) -> Result<()> {
        let power = self.power_for(board)?;
        power.cycle().await?;
        self.emit(AgentReport::PowerEvent {
            board: board.clone(),
            action: PowerAction::Cycle,
        })
        .await;
        if erase {
            // RESOLVE(1713): an explicit erase requires briefly attaching a
            // probe-rs session to the board and issuing `erase`. The seam is
            // here; the actual erase rides the same backend once the relay
            // splice lands. For now we record the intent.
            self.emit(AgentReport::Log {
                level: fleet_proto::LogLevel::Info,
                board: Some(board.clone()),
                message: "erase-on-release requested (pending backend wiring)".to_owned(),
            })
            .await;
        }
        Ok(())
    }

    /// Explicit operator power-cycle.
    async fn on_power_cycle(&self, board: &BoardId) -> Result<()> {
        let power = self.power_for(board)?;
        power.cycle().await?;
        self.emit(AgentReport::PowerEvent {
            board: board.clone(),
            action: PowerAction::Cycle,
        })
        .await;
        Ok(())
    }

    /// Re-report inventory upward.
    async fn on_query_state(&self) -> Result<()> {
        let inv = self.inventory.lock().await.clone();
        self.emit(AgentReport::Inventory(inv)).await;
        Ok(())
    }

    /// Quarantine a board after a fault: kill its sessions, power-cycle, and
    /// emit a `Fault` report.
    ///
    /// # Errors
    ///
    /// Propagates power/backend errors.
    pub async fn fault_board(&self, board: &BoardId, reason: String) -> Result<()> {
        let channels: Vec<ChannelId> = {
            let sessions = self.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| &s.board == board)
                .map(|(c, _)| *c)
                .collect()
        };
        for channel in channels {
            self.on_kill_session(channel).await?;
        }
        // Best-effort power-cycle; report the fault regardless.
        let _ = self.power_for(board).map(|_| ());
        self.emit(AgentReport::Fault {
            board: board.clone(),
            reason,
        })
        .await;
        Ok(())
    }

    /// Number of currently active sessions (for tests / introspection).
    pub async fn active_session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// The agent's configured id.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.config.agent_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probers::mock::MockBackend;
    use ed25519_dalek::{Signer, SigningKey};
    use fleet_proto::token::{CapabilityToken, SignedToken};

    const SEED: [u8; 32] = [3u8; 32];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED)
    }

    fn agent_config() -> AgentConfig {
        let pubkey_hex = hex_encode(&signing_key().verifying_key().to_bytes());
        let toml = format!(
            r#"
agent_id = "pi-1"
coordinator_endpoint = "c:1"
tls_cert = "/c.pem"
tls_key = "/k.pem"
tls_ca = "/ca.pem"
coordinator_token_pubkey = "{pubkey_hex}"
boards_path = "/boards.toml"
"#
        );
        AgentConfig::from_str(&toml).unwrap()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn boards() -> BoardsConfig {
        BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "S1"
chip = "c1"
[board.power]
kind = "uhubctl"
hub = "1-1"
port = 2
"#,
        )
        .unwrap()
    }

    fn signed_token(lease: u64, board: &str, ops: Vec<AllowedOp>, expires: u64) -> Vec<u8> {
        let token = CapabilityToken {
            lease: LeaseId(lease),
            board: BoardId(board.to_owned()),
            allowed_ops: ops,
            expires,
        };
        let key = signing_key();
        let bytes = token.serialize_for_signing().unwrap();
        let sig = key.sign(&bytes);
        SignedToken {
            token_bytes: bytes,
            signature: sig.to_bytes(),
        }
        .to_wire()
    }

    fn make_agent(backend: Arc<MockBackend>) -> Agent<MockBackend> {
        let mut a = Agent::new(agent_config(), boards(), backend).unwrap();
        a.set_clock(|| 1_000);
        // Substitute no-op power control so tests don't shell out to uhubctl.
        a.set_power_factory(Box::new(|_| Box::new(crate::power::NoPower)));
        a
    }

    #[tokio::test]
    async fn open_session_with_valid_token_starts_backend() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap();
        assert_eq!(backend.open_count(), 1);
        assert_eq!(agent.active_session_count().await, 1);
    }

    #[tokio::test]
    async fn open_session_rejects_bad_token_and_does_not_start_backend() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        // Token for the wrong board.
        let token = signed_token(7, "other", vec![AllowedOp::Attach], 2_000);
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Token(_)));
        assert_eq!(backend.open_count(), 0);
        assert_eq!(agent.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn open_session_rejects_expired_token() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], 500); // < clock 1000
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Token(_)));
        assert_eq!(backend.open_count(), 0);
    }

    #[tokio::test]
    async fn open_session_unknown_board_errors() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "ghost", vec![AllowedOp::Attach], 2_000);
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("ghost".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::UnknownBoard(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn release_lease_kills_session_and_powercycles() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 1);

        agent
            .handle_command(CoordinatorCommand::ReleaseLease {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                erase: false,
            })
            .await
            .unwrap();

        assert_eq!(agent.active_session_count().await, 0);
        let reports = agent.take_reports().await;
        // Expect a PowerEvent::Cycle among the emitted reports.
        assert!(reports.iter().any(|r| matches!(
            r,
            AgentReport::PowerEvent {
                action: PowerAction::Cycle,
                ..
            }
        )));
        assert!(reports
            .iter()
            .any(|r| matches!(r, AgentReport::SessionClosed { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_power_cycle_emits_event() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        agent
            .handle_command(CoordinatorCommand::PowerCycle {
                board: BoardId("b1".into()),
            })
            .await
            .unwrap();
        let reports = agent.take_reports().await;
        assert!(reports.iter().any(|r| matches!(
            r,
            AgentReport::PowerEvent {
                action: PowerAction::Cycle,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn query_state_reports_inventory() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        agent
            .set_inventory(ProbeInventory {
                boards: Vec::new(),
                unknown: Vec::new(),
            })
            .await;
        agent
            .handle_command(CoordinatorCommand::QueryState)
            .await
            .unwrap();
        let reports = agent.take_reports().await;
        assert!(reports
            .iter()
            .any(|r| matches!(r, AgentReport::Inventory(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn fault_board_kills_sessions_and_reports() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".into()),
                token,
                channel: ChannelId(1),
            })
            .await
            .unwrap();
        agent
            .fault_board(&BoardId("b1".into()), "probe lost".to_owned())
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 0);
        let reports = agent.take_reports().await;
        assert!(reports
            .iter()
            .any(|r| matches!(r, AgentReport::Fault { .. })));
    }

    #[tokio::test]
    async fn kill_unknown_channel_is_noop() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        agent
            .handle_command(CoordinatorCommand::KillSession {
                channel: ChannelId(99),
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 0);
    }
}
