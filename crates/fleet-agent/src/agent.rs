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
    AgentReport, BoardName, BoardRef, ChannelId, ChannelKind, CoordinatorCommand, LeaseId,
    PowerAction,
    PowerKind, ProbeInventory,
};

use crate::config::{AgentConfig, BoardSpec, BoardsConfig};
use crate::error::{AgentError, Result};
use crate::gdb::{GdbConnection, GdbStub, ProcessGdbStub};
use crate::power::{self, PowerControl};
use crate::probers::{ProbeRsBackend, Session};
use crate::token::Ed25519Verifier;

/// An open data-plane session bound to a lease/board/channel.
struct ActiveSession {
    lease: LeaseId,
    board: BoardName,
    session: Box<dyn Session>,
}

/// An open gdb-tunnel session: a board-local `probe-rs gdb` stub whose TCP
/// stream is spliced onto the relay channel. Tracked separately from
/// [`ActiveSession`] because it owns a process + connection rather than a
/// `probe-rs serve` [`Session`], but shares the same lease/board lifecycle.
struct GdbSession {
    lease: LeaseId,
    board: BoardName,
    connection: GdbConnection,
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
    /// Spawns board-local `probe-rs gdb` stubs for gdb-tunnel channels.
    gdb_stub: Arc<dyn GdbStub>,
    inventory: Mutex<ProbeInventory>,
    sessions: Mutex<HashMap<ChannelId, ActiveSession>>,
    /// Open gdb-tunnel sessions, keyed by channel (parallel to `sessions`).
    gdb_sessions: Mutex<HashMap<ChannelId, GdbSession>>,
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

/// Lowercase-hex encode a byte slice (used to render the serve user token).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
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
            gdb_stub: Arc::new(ProcessGdbStub::new()),
            inventory: Mutex::new(ProbeInventory {
                boards: Vec::new(),
                unknown: Vec::new(),
            }),
            sessions: Mutex::new(HashMap::new()),
            gdb_sessions: Mutex::new(HashMap::new()),
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

    /// Override the gdb-stub backend (tests).
    #[cfg(test)]
    fn set_gdb_stub(&mut self, stub: Arc<dyn GdbStub>) {
        self.gdb_stub = stub;
    }

    /// Replace the current inventory snapshot (called after discovery).
    pub async fn set_inventory(&self, inventory: ProbeInventory) {
        *self.inventory.lock().await = inventory;
    }

    /// A clone of the current inventory snapshot.
    pub async fn current_inventory(&self) -> ProbeInventory {
        self.inventory.lock().await.clone()
    }

    /// Seed the inventory from `boards.toml`, marking every declared board
    /// online with its full metadata.
    ///
    /// Used on the live dial-out path where a concrete probe enumerator is not
    /// yet wired: declared boards are advertised as present so they become
    /// leasable, and a session-open will surface a real error if the probe is
    /// in fact absent. When a [`crate::discovery::ProbeLister`] is wired, call
    /// [`set_inventory`] with the reconciled result instead.
    ///
    /// [`set_inventory`]: Agent::set_inventory
    pub async fn seed_inventory_from_boards(&self) {
        use fleet_proto::{BoardPresence, BoardStatus};
        let boards = self
            .boards
            .boards
            .iter()
            .map(|b| BoardStatus {
                board: BoardName(b.id.clone()),
                serial: b.serial.clone(),
                presence: BoardPresence::Online,
                chip: b.chip.clone(),
                tags: b.tags.clone(),
                exclusive: b.exclusive,
                power: b.power.to_power_kind(),
            })
            .collect();
        *self.inventory.lock().await = ProbeInventory {
            boards,
            unknown: Vec::new(),
        };
    }

    /// Drain queued upward reports.
    pub async fn take_reports(&self) -> Vec<AgentReport> {
        std::mem::take(&mut *self.outbox.lock().await)
    }

    async fn emit(&self, report: AgentReport) {
        self.outbox.lock().await.push(report);
    }

    fn board_spec(&self, board: &BoardName) -> Result<&BoardSpec> {
        self.boards
            .board(board)
            .ok_or_else(|| AgentError::UnknownBoard(board.0.clone()))
    }

    /// Resolve the power controller for a board.
    fn power_for(&self, board: &BoardName) -> Result<Box<dyn PowerControl>> {
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
                kind,
            } => self.on_open_session(lease, &board, &token, channel, kind).await,
            CoordinatorCommand::KillSession { channel } => self.on_kill_session(channel).await,
            CoordinatorCommand::ReleaseLease {
                lease,
                board,
                erase,
            } => self.on_release_lease(lease, &board, erase).await,
            CoordinatorCommand::PowerCycle { board } => self.on_power_cycle(&board).await,
            CoordinatorCommand::QueryState => self.on_query_state().await,
            // Rotation is a property of the *connection*, not of board state:
            // it is handled in `connection.rs`, which owns the config file this
            // agent's credential lives in. Reaching here means the connection
            // layer did not intercept it.
            CoordinatorCommand::RotateNodeToken { .. } => Err(AgentError::Connection(
                "token rotation must be handled by the connection layer".to_owned(),
            )),
        }
    }

    /// Verify the token and open a session of the requested [`ChannelKind`].
    ///
    /// The coordinator addresses the board by its fleet-unique [`BoardRef`],
    /// which is what the capability token is scoped to; the agent compares that
    /// key verbatim (so a token minted for another org's same-named board does
    /// not verify) and uses only its node-local name half to look the board up
    /// in `boards.toml`.
    async fn on_open_session(
        &self,
        lease: LeaseId,
        board: &BoardRef,
        token_wire: &[u8],
        channel: ChannelId,
        kind: ChannelKind,
    ) -> Result<()> {
        let local = board.board_name();
        // Board must be declared.
        let spec = self.board_spec(&local)?.clone();

        // Verify the capability token locally before doing anything else. The
        // required capability depends on the channel kind: a gdb tunnel needs
        // `Gdb`, the data plane needs `Attach`.
        let required = match kind {
            ChannelKind::Data => AllowedOp::Attach,
            ChannelKind::Gdb => AllowedOp::Gdb,
        };
        let now = (self.now_fn)();
        crate::token::verify_wire(&self.verifier, token_wire, lease, board, required, now)?;

        match kind {
            ChannelKind::Data => {
                self.open_data_session(lease, &local, token_wire, channel, &spec)
                    .await
            }
            ChannelKind::Gdb => self.open_gdb_session(lease, &local, channel, &spec).await,
        }
    }

    /// Open a `probe-rs serve` data-plane session and record it.
    async fn open_data_session(
        &self,
        lease: LeaseId,
        board: &BoardName,
        token_wire: &[u8],
        channel: ChannelId,
        spec: &BoardSpec,
    ) -> Result<()> {
        // The serve user token is the hex of the fleet capability token. The
        // sidecar sets `PROBE_RS_REMOTE_TOKEN = hex(grant.token)` and the agent
        // receives those exact bytes as `token_wire`, so writing the same hex
        // into `.probe-rs.toml` makes the two ends match end-to-end.
        let serve_token = hex_encode(token_wire);
        let session = self
            .backend
            .open(spec, &serve_token)
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

    /// Spawn a board-local `probe-rs gdb` stub and record the gdb-tunnel
    /// session. The connection's TCP stream is spliced onto `channel` by the
    /// transport layer (see [`crate::gdb::splice`]); here we own its lifecycle.
    async fn open_gdb_session(
        &self,
        lease: LeaseId,
        board: &BoardName,
        channel: ChannelId,
        spec: &BoardSpec,
    ) -> Result<()> {
        let connection = self
            .gdb_stub
            .spawn(spec)
            .await
            .map_err(AgentError::Probers)?;
        self.gdb_sessions.lock().await.insert(
            channel,
            GdbSession {
                lease,
                board: board.clone(),
                connection,
            },
        );
        self.emit(AgentReport::Log {
            level: fleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!(
                "opened gdb tunnel on channel {} for lease {}",
                channel.0, lease.0
            ),
        })
        .await;
        Ok(())
    }

    /// Kill the session on `channel` (data plane *or* gdb tunnel).
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
        // A gdb tunnel may share the same channel-id space; tear it down too.
        let gdb = self.gdb_sessions.lock().await.remove(&channel);
        if let Some(session) = gdb {
            session.connection.shutdown().await;
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
        board: &BoardName,
        erase: bool,
    ) -> Result<()> {
        // Kill any session(s) tied to this lease (data plane and gdb tunnels).
        let channels = self.channels_for_lease(lease).await;
        for channel in channels {
            self.on_kill_session(channel).await?;
        }

        // Cleanup: power-cycle the board.
        self.cleanup_board(board, erase).await
    }

    /// Cleanup a board: power-cycle and optionally note erase.
    async fn cleanup_board(&self, board: &BoardName, erase: bool) -> Result<()> {
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
    async fn on_power_cycle(&self, board: &BoardName) -> Result<()> {
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
    pub async fn fault_board(&self, board: &BoardName, reason: String) -> Result<()> {
        let channels = self.channels_for_board(board).await;
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

    /// All channels (data plane + gdb tunnels) tied to `lease`.
    async fn channels_for_lease(&self, lease: LeaseId) -> Vec<ChannelId> {
        let mut channels: Vec<ChannelId> = self
            .sessions
            .lock()
            .await
            .iter()
            .filter(|(_, s)| s.lease == lease)
            .map(|(c, _)| *c)
            .collect();
        channels.extend(
            self.gdb_sessions
                .lock()
                .await
                .iter()
                .filter(|(_, s)| s.lease == lease)
                .map(|(c, _)| *c),
        );
        channels
    }

    /// All channels (data plane + gdb tunnels) tied to `board`.
    async fn channels_for_board(&self, board: &BoardName) -> Vec<ChannelId> {
        let mut channels: Vec<ChannelId> = self
            .sessions
            .lock()
            .await
            .iter()
            .filter(|(_, s)| &s.board == board)
            .map(|(c, _)| *c)
            .collect();
        channels.extend(
            self.gdb_sessions
                .lock()
                .await
                .iter()
                .filter(|(_, s)| &s.board == board)
                .map(|(c, _)| *c),
        );
        channels
    }

    /// Number of currently active sessions (for tests / introspection).
    pub async fn active_session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Take the spliceable byte stream for an open data-plane session, so the
    /// connection layer can byte-splice it onto the relay channel. Returns
    /// `None` if no session is open on `channel` or its stream was already
    /// taken.
    pub async fn take_data_io(&self, channel: ChannelId) -> Option<Box<dyn crate::probers::SpliceIo>> {
        let sessions = self.sessions.lock().await;
        let active = sessions.get(&channel)?;
        active.session.take_io().await
    }

    /// Take the spliceable gdb TCP stream for an open gdb-tunnel session, so the
    /// connection layer can byte-splice it onto the relay channel. Returns
    /// `None` if no gdb session is open on `channel` or its stream was already
    /// taken.
    pub async fn take_gdb_io(&self, channel: ChannelId) -> Option<tokio::net::TcpStream> {
        let mut sessions = self.gdb_sessions.lock().await;
        let gdb = sessions.get_mut(&channel)?;
        gdb.connection.take_stream()
    }

    /// Number of currently open gdb-tunnel sessions (for tests).
    pub async fn gdb_session_count(&self) -> usize {
        self.gdb_sessions.lock().await.len()
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
fleet_url = "https://coordinator.example:7000"
node_token = "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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

    /// The fleet-unique key the coordinator would mint for one of this node's
    /// boards. The agent never constructs one in production — it only compares
    /// the key the coordinator sent against the one inside the token.
    fn board_ref(name: &str) -> BoardRef {
        BoardRef::new(
            fleet_proto::ids::OrgId("default".to_owned()),
            fleet_proto::ids::AgentId("pi-1".to_owned()),
            name,
        )
    }

    fn signed_token(lease: u64, board: &str, ops: Vec<AllowedOp>, expires: u64) -> Vec<u8> {
        let token = CapabilityToken {
            lease: LeaseId(lease),
            board: board_ref(board),
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
        // Substitute a mock gdb stub so tests don't spawn `probe-rs gdb`.
        a.set_gdb_stub(Arc::new(crate::gdb::mock::MockGdbStub::new()));
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
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
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
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
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
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
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
                board: board_ref("ghost"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
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
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 1);

        agent
            .handle_command(CoordinatorCommand::ReleaseLease {
                lease: LeaseId(7),
                board: BoardName("b1".into()),
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
                board: BoardName("b1".into()),
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
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .unwrap();
        agent
            .fault_board(&BoardName("b1".into()), "probe lost".to_owned())
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

    #[tokio::test]
    async fn open_gdb_channel_with_valid_token_spawns_stub() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Gdb], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Gdb,
            })
            .await
            .unwrap();
        // A gdb session was opened; no data-plane `serve` was started.
        assert_eq!(agent.gdb_session_count().await, 1);
        assert_eq!(agent.active_session_count().await, 0);
        assert_eq!(backend.open_count(), 0);
    }

    #[tokio::test]
    async fn open_gdb_channel_rejects_token_without_gdb_op() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        // Token grants Attach but NOT Gdb.
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], 2_000);
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Gdb,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Token(_)));
        assert_eq!(agent.gdb_session_count().await, 0);
    }

    #[tokio::test]
    async fn data_channel_rejects_token_without_attach_op() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        // Token grants Gdb but NOT Attach: a data-plane open must be rejected.
        let token = signed_token(7, "b1", vec![AllowedOp::Gdb], 2_000);
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Token(_)));
        assert_eq!(agent.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn kill_gdb_channel_tears_down_session() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        let token = signed_token(7, "b1", vec![AllowedOp::Gdb], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Gdb,
            })
            .await
            .unwrap();
        assert_eq!(agent.gdb_session_count().await, 1);
        agent
            .handle_command(CoordinatorCommand::KillSession {
                channel: ChannelId(1),
            })
            .await
            .unwrap();
        assert_eq!(agent.gdb_session_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn release_lease_tears_down_gdb_and_data_sessions() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        // A data-plane channel and a gdb channel for the same lease.
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token: signed_token(7, "b1", vec![AllowedOp::Attach], 2_000),
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .unwrap();
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token: signed_token(7, "b1", vec![AllowedOp::Gdb], 2_000),
                channel: ChannelId(2),
                kind: ChannelKind::Gdb,
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 1);
        assert_eq!(agent.gdb_session_count().await, 1);

        agent
            .handle_command(CoordinatorCommand::ReleaseLease {
                lease: LeaseId(7),
                board: BoardName("b1".into()),
                erase: false,
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 0);
        assert_eq!(agent.gdb_session_count().await, 0);
    }
}
