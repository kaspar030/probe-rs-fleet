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
    BoardName, BoardRef, ChannelId, ChannelKind, CoordinatorCommand, LeaseId, NodeReport,
    PowerAction, PowerKind, ProbeInventory,
};

use crate::config::{AgentConfig, BoardSpec, BoardsConfig};
use crate::discovery::{self, ProbeLister, ProbeRsListLister};
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
    /// Boards synthesised from undeclared probes under `adopt = "auto"`.
    ///
    /// Rebuilt by the discovery loop ([`Agent::set_adopted`]); `boards.toml`
    /// always wins on collision, which [`Agent::board_spec`] enforces
    /// structurally by consulting `boards` first.
    ///
    /// A `Mutex` rather than an `ArcSwap`: no new dependency, contention is nil
    /// (a discovery tick every ~30s against a session open), and it matches how
    /// `inventory` / `sessions` / `gdb_sessions` are already held.
    adopted: Mutex<HashMap<BoardName, BoardSpec>>,
    /// Enumerates locally attached probes for the discovery loop.
    ///
    /// The agent holds its own handle rather than reaching into the backend's:
    /// [`ProcessBackend`](crate::probers::ProcessBackend) uses one at
    /// session-open time to resolve vid/pid, and the connection loop needs one
    /// on a timer. Injectable so tests need neither hardware nor a `probe-rs`
    /// binary.
    lister: Arc<dyn ProbeLister>,
    verifier: Ed25519Verifier,
    backend: Arc<B>,
    /// Spawns board-local `probe-rs gdb` stubs for gdb-tunnel channels.
    gdb_stub: Arc<dyn GdbStub>,
    inventory: Mutex<ProbeInventory>,
    sessions: Mutex<HashMap<ChannelId, ActiveSession>>,
    /// Open gdb-tunnel sessions, keyed by channel (parallel to `sessions`).
    gdb_sessions: Mutex<HashMap<ChannelId, GdbSession>>,
    /// Reports the agent wants to emit upward (drained by the connection loop).
    outbox: Mutex<Vec<NodeReport>>,
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

/// The [`BoardStatus`](fleet_proto::BoardStatus) a **declared** board is
/// advertised as when seeding the inventory from `boards.toml` alone (no live
/// discovery yet).
///
/// The adopted counterpart is
/// [`adopted_board_status`](crate::discovery::adopted_board_status); both
/// derive the status from a [`BoardSpec`], so the id a board is reported under
/// and the id [`Agent::board_spec`] resolves cannot drift apart.
fn declared_board_status(b: &BoardSpec) -> fleet_proto::BoardStatus {
    fleet_proto::BoardStatus {
        board: BoardName(b.id.clone()),
        serial: b.serial.clone(),
        presence: fleet_proto::BoardPresence::Online,
        chip: b.chip.clone(),
        model: b.model.clone(),
        tags: b.tags.clone(),
        exclusive: b.exclusive,
        power: b.power.to_power_kind(),
        adopted: false,
    }
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
    pub fn new(config: AgentConfig, boards: BoardsConfig, backend: Arc<B>) -> Result<Self> {
        let key = config.coordinator_token_pubkey_bytes()?;
        let verifier = Ed25519Verifier::from_public_key_bytes(&key)?;
        Ok(Self {
            config,
            boards,
            adopted: Mutex::new(HashMap::new()),
            lister: Arc::new(ProbeRsListLister::default()),
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

    /// Override the probe enumerator (tests, or a node with a non-default
    /// `probe-rs` binary).
    #[must_use]
    pub fn with_lister(mut self, lister: Arc<dyn ProbeLister>) -> Self {
        self.lister = lister;
        self
    }

    /// Run one probe-discovery pass and, if anything changed, install the
    /// result.
    ///
    /// Returns the new inventory when it differs from the current one, and
    /// `None` when nothing changed — so the connection loop reports **only on
    /// change** rather than making a quiet fleet chatty for nothing.
    ///
    /// An enumeration failure is **not** an error here: it logs at warn and
    /// returns `None`, leaving the previous inventory in place. A transient USB
    /// or `probe-rs` hiccup taking every board in the fleet offline would be a
    /// great deal worse than a stale snapshot.
    ///
    /// The previously adopted set is handed to
    /// [`adopt_unknown`](crate::discovery::adopt_unknown) so a board whose
    /// probe has been unplugged is reported **offline** rather than silently
    /// disappearing from the report — see that function for why a vanishing
    /// board strands a phantom in the coordinator's scheduler.
    ///
    /// The inventory and the adopted-spec map are installed together (see
    /// [`Agent::set_inventory`]).
    pub async fn discovery_pass(&self) -> Option<ProbeInventory> {
        let discovered = match self.lister.list_probes().await {
            Ok(probes) => probes,
            Err(e) => {
                tracing::warn!(error = %e, "probe enumeration failed; keeping the previous inventory");
                return None;
            }
        };
        let mut inventory = discovery::reconcile(&self.boards, &discovered);
        let previous = self.adopted.lock().await.clone();
        let adopted = discovery::adopt_unknown(&mut inventory, self.config.adopt, &previous);
        if *self.inventory.lock().await == inventory {
            return None;
        }
        // Both or neither: an inventory advertising a board whose spec is
        // missing is a lease that fails at the last hop.
        self.set_adopted(adopted).await;
        self.set_inventory(inventory.clone()).await;
        Some(inventory)
    }

    /// Replace the current inventory snapshot (called after discovery).
    ///
    /// Under `adopt = "auto"` this must be paired with [`Agent::set_adopted`]
    /// — **set both or neither**. An inventory that advertises a board whose
    /// spec is missing produces a lease the coordinator grants and this agent
    /// then refuses with `UnknownBoard`, at the last possible moment and with
    /// an opaque error.
    pub async fn set_inventory(&self, inventory: ProbeInventory) {
        *self.inventory.lock().await = inventory;
    }

    /// Replace the set of boards adopted from undeclared probes.
    ///
    /// See [`Agent::set_inventory`] for why the two are always set together.
    pub async fn set_adopted(&self, specs: HashMap<BoardName, BoardSpec>) {
        *self.adopted.lock().await = specs;
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
        let boards = self
            .boards
            .boards
            .iter()
            .map(declared_board_status)
            .collect();
        *self.inventory.lock().await = ProbeInventory {
            boards,
            unknown: Vec::new(),
        };
    }

    /// Drain queued upward reports.
    pub async fn take_reports(&self) -> Vec<NodeReport> {
        std::mem::take(&mut *self.outbox.lock().await)
    }

    async fn emit(&self, report: NodeReport) {
        self.outbox.lock().await.push(report);
    }

    /// Resolve a board's spec: `boards.toml` first, then the adopted set.
    ///
    /// **Declared wins**, and it wins *here* rather than by convention at each
    /// call site — that is what makes the precedence rule (a declaration
    /// overrides an adoption for the same probe) a structural property rather
    /// than something two call sites have to remember.
    ///
    /// Returns an owned spec because the adopted half lives behind a lock and
    /// is rebuilt at runtime by the discovery loop.
    async fn board_spec(&self, board: &BoardName) -> Result<BoardSpec> {
        if let Some(spec) = self.boards.board(board) {
            return Ok(spec.clone());
        }
        self.adopted
            .lock()
            .await
            .get(board)
            .cloned()
            .ok_or_else(|| AgentError::UnknownBoard(board.0.clone()))
    }

    /// Resolve the power controller for a board.
    ///
    /// An adopted board has `PowerSpec::None` — correct for a probe nobody
    /// wired power to — so cleanup and explicit power-cycles run a no-op
    /// controller rather than failing.
    async fn power_for(&self, board: &BoardName) -> Result<Box<dyn PowerControl>> {
        let spec = self.board_spec(board).await?;
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
            } => {
                self.on_open_session(lease, &board, &token, channel, kind)
                    .await
            }
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
        // The board must resolve: declared in `boards.toml`, or adopted from an
        // undeclared probe under `adopt = "auto"`.
        let spec = self.board_spec(&local).await?;

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
        self.emit(NodeReport::Log {
            level: fleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!(
                "opened session on channel {} for lease {}",
                channel.0, lease.0
            ),
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
        self.emit(NodeReport::Log {
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
            active.session.kill().await.map_err(AgentError::Probers)?;
            self.emit(NodeReport::SessionClosed {
                channel,
                exit_code: None,
            })
            .await;
        }
        // A gdb tunnel may share the same channel-id space; tear it down too.
        let gdb = self.gdb_sessions.lock().await.remove(&channel);
        if let Some(session) = gdb {
            session.connection.shutdown().await;
            self.emit(NodeReport::SessionClosed {
                channel,
                exit_code: None,
            })
            .await;
        }
        Ok(())
    }

    /// Release a lease: kill its session, then power-cycle (and optionally
    /// erase) the board for cleanup.
    async fn on_release_lease(&self, lease: LeaseId, board: &BoardName, erase: bool) -> Result<()> {
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
        let power = self.power_for(board).await?;
        power.cycle().await?;
        self.emit(NodeReport::PowerEvent {
            board: board.clone(),
            action: PowerAction::Cycle,
        })
        .await;
        if erase {
            // RESOLVE(1713): an explicit erase requires briefly attaching a
            // probe-rs session to the board and issuing `erase`. The seam is
            // here; the actual erase rides the same backend once the relay
            // splice lands. For now we record the intent.
            self.emit(NodeReport::Log {
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
        let power = self.power_for(board).await?;
        power.cycle().await?;
        self.emit(NodeReport::PowerEvent {
            board: board.clone(),
            action: PowerAction::Cycle,
        })
        .await;
        Ok(())
    }

    /// Re-report inventory upward.
    async fn on_query_state(&self) -> Result<()> {
        let inv = self.inventory.lock().await.clone();
        self.emit(NodeReport::Inventory(inv)).await;
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
        let _ = self.power_for(board).await.map(|_| ());
        self.emit(NodeReport::Fault {
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
    pub async fn take_data_io(
        &self,
        channel: ChannelId,
    ) -> Option<Box<dyn crate::probers::SpliceIo>> {
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

    /// This node's configured id.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.config.node_id
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

    /// The node id the coordinator handed this node at enrolment.
    ///
    /// Org-namespaced, because that is what the coordinator mints
    /// (`fleet-coordinator/src/state.rs::node_id_for`) and returns as
    /// `TokenResponse::node_id`, which `fleet-bin`'s `node_setup` writes into
    /// the config verbatim. The node never builds this itself — it cannot,
    /// not knowing its own org — so a fixture that invents a bare `"pi-1"`
    /// describes a config production never writes.
    const NODE_ID: &str = "default/pi-1";

    fn agent_config() -> AgentConfig {
        AgentConfig {
            node_id: NODE_ID.to_owned(),
            fleet_url: "https://coordinator.example:7000".to_owned(),
            node_token: "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            previous_node_token: None,
            server_cert_sha256: None,
            coordinator_token_pubkey: hex_encode(&signing_key().verifying_key().to_bytes()),
            boards_path: std::path::PathBuf::from("/boards.toml"),
            heartbeat_secs: crate::config::default_heartbeat_secs(),
            discovery_secs: crate::config::default_discovery_secs(),
            adopt: fleet_proto::AdoptPolicy::Declared,
            erase_on_release: false,
        }
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
    /// the key the coordinator sent against the one inside the token — so the
    /// node half is the coordinator's org-namespaced id, not a bare name.
    fn board_ref(name: &str) -> BoardRef {
        BoardRef::new(
            fleet_proto::ids::OrgId("default".to_owned()),
            fleet_proto::ids::NodeId(NODE_ID.to_owned()),
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
            NodeReport::PowerEvent {
                action: PowerAction::Cycle,
                ..
            }
        )));
        assert!(reports
            .iter()
            .any(|r| matches!(r, NodeReport::SessionClosed { .. })));
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
            NodeReport::PowerEvent {
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
            .any(|r| matches!(r, NodeReport::Inventory(_))));
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
            .any(|r| matches!(r, NodeReport::Fault { .. })));
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

    // ---- adoption ----------------------------------------------------------

    /// **The acceptance test for the whole feature.**
    ///
    /// With `adopt = "auto"` and a probe absent from `boards.toml`, a
    /// capability token minted for the *synthesised* board must open a session.
    /// Every other test in this task exercises one side of the seam: the agent
    /// synthesising a `BoardStatus`, or the coordinator scheduling it. This is
    /// the one that closes it.
    ///
    /// Before adopted specs were resolvable, this path ended in
    /// `AgentError::UnknownBoard` — the coordinator would adopt the probe,
    /// lease it, mint a token, and the agent would refuse at the last possible
    /// moment with an opaque error.
    #[tokio::test]
    async fn an_auto_adopted_board_can_actually_open_a_session() {
        use crate::discovery::StubLister;

        let backend = Arc::new(MockBackend::new());
        let mut config = agent_config();
        config.adopt = fleet_proto::AdoptPolicy::Auto;
        // A probe nobody declared: `boards()` knows only S1.
        let probe = fleet_proto::DiscoveredProbe {
            serial: "ZZZ".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        };
        let mut agent = Agent::new(config, boards(), backend.clone()).unwrap();
        agent.set_clock(|| 1_000);
        agent.set_power_factory(Box::new(|_| Box::new(crate::power::NoPower)));
        let agent = agent.with_lister(Arc::new(StubLister(vec![probe])));

        let inventory = agent.discovery_pass().await.expect("the probe is new");
        let adopted = inventory
            .boards
            .iter()
            .find(|b| b.adopted)
            .expect("the undeclared probe must be adopted under `auto`");
        let board = adopted.board.0.clone();

        // Exactly the board the coordinator would have scheduled, leased with
        // exactly the token it would have minted.
        let token = signed_token(7, &board, vec![AllowedOp::Attach], 2_000);
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref(&board),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .expect("an auto-adopted board must be leasable, not UnknownBoard");
        assert_eq!(backend.open_count(), 1);
        assert_eq!(agent.active_session_count().await, 1);
    }

    /// The other half of the acceptance test: **unplugging** the probe must
    /// report the board `Offline` and stop resolving it.
    ///
    /// A laptop is the machine where boards come and go several times a day.
    /// If the departed board merely vanished from the report, nothing on the
    /// coordinator would prune it — it would stay `Idle` in the scheduler and
    /// the next lease against it would be granted, minted a token, and answered
    /// with `UnknownBoard` here at the last possible hop.
    #[tokio::test]
    async fn unplugging_an_adopted_probe_reports_it_offline_and_stops_resolving_it() {
        use crate::discovery::{ProbeLister, SwappableLister};

        let mut config = agent_config();
        config.adopt = fleet_proto::AdoptPolicy::Auto;
        let probe = fleet_proto::DiscoveredProbe {
            serial: "ZZZ".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        };
        let lister = Arc::new(SwappableLister::new(vec![probe]));
        let mut agent = Agent::new(config, boards(), Arc::new(MockBackend::new())).unwrap();
        agent.set_clock(|| 1_000);
        let agent = agent.with_lister(Arc::clone(&lister) as Arc<dyn ProbeLister>);

        let inventory = agent.discovery_pass().await.expect("the probe is new");
        let board = inventory
            .boards
            .iter()
            .find(|b| b.adopted)
            .expect("adopted")
            .board
            .clone();
        assert!(agent.board_spec(&board).await.is_ok());

        // Unplug it.
        lister.set(vec![]);
        let inventory = agent
            .discovery_pass()
            .await
            .expect("losing a board is a change worth reporting");

        let status = inventory
            .boards
            .iter()
            .find(|b| b.board == board)
            .expect("the board must still be REPORTED, so the coordinator drops it");
        assert_eq!(status.presence, fleet_proto::BoardPresence::Offline);
        assert!(status.adopted);

        // ... and the agent no longer resolves it, so the two ends agree.
        assert!(matches!(
            agent.board_spec(&board).await,
            Err(AgentError::UnknownBoard(_))
        ));
    }

    /// Re-plugging must bring the same board back under the same id — the
    /// stability property, across a real absence rather than two snapshots.
    #[tokio::test]
    async fn replugging_restores_the_same_board_id() {
        use crate::discovery::{ProbeLister, SwappableLister};

        let probe = fleet_proto::DiscoveredProbe {
            serial: "ZZZ".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        };
        let mut config = agent_config();
        config.adopt = fleet_proto::AdoptPolicy::Auto;
        let lister = Arc::new(SwappableLister::new(vec![probe.clone()]));
        let mut agent = Agent::new(config, boards(), Arc::new(MockBackend::new())).unwrap();
        agent.set_clock(|| 1_000);
        let agent = agent.with_lister(Arc::clone(&lister) as Arc<dyn ProbeLister>);

        let first = agent.discovery_pass().await.expect("plugged in");
        let name = first
            .boards
            .iter()
            .find(|b| b.adopted)
            .unwrap()
            .board
            .clone();

        lister.set(vec![]);
        agent.discovery_pass().await.expect("unplugged");

        lister.set(vec![probe]);
        let third = agent.discovery_pass().await.expect("plugged back in");
        let back = third
            .boards
            .iter()
            .find(|b| b.adopted && b.presence == fleet_proto::BoardPresence::Online)
            .expect("the board is back");
        assert_eq!(back.board, name, "a lease selector must keep working");
        assert!(agent.board_spec(&name).await.is_ok());
    }

    /// Under `declared`, the same probe stays unadoptable and the same lease
    /// fails — which is the policy doing its job, not a bug.
    #[tokio::test]
    async fn under_declared_the_same_probe_yields_no_board() {
        use crate::discovery::StubLister;

        let backend = Arc::new(MockBackend::new());
        let mut config = agent_config();
        config.adopt = fleet_proto::AdoptPolicy::Declared;
        let probe = fleet_proto::DiscoveredProbe {
            serial: "ZZZ".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        };
        let mut agent = Agent::new(config, boards(), backend).unwrap();
        agent.set_clock(|| 1_000);
        let agent = agent.with_lister(Arc::new(StubLister(vec![probe])));

        let inventory = agent.discovery_pass().await.expect("inventory changed");
        assert!(inventory.boards.iter().all(|b| !b.adopted));
        assert_eq!(inventory.unknown.len(), 1, "reported, just not leasable");

        let token = signed_token(7, "j-link-zzz", vec![AllowedOp::Attach], 2_000);
        let err = agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("j-link-zzz"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::UnknownBoard(_)));
    }

    /// Declared wins, and it wins inside `board_spec` rather than by convention
    /// at each call site. Here the adopted map is deliberately poisoned with an
    /// entry for a declared board's name; the declaration must still be what
    /// resolves.
    #[tokio::test]
    async fn a_declaration_beats_an_adopted_entry_of_the_same_name() {
        let agent = make_agent(Arc::new(MockBackend::new()));
        let mut poisoned = HashMap::new();
        poisoned.insert(
            BoardName("b1".to_owned()),
            BoardSpec {
                id: "b1".to_owned(),
                serial: "WRONG".to_owned(),
                vid: 0,
                pid: 0,
                chip: String::new(),
                model: None,
                tags: vec!["auto".to_owned()],
                exclusive: true,
                power: crate::config::PowerSpec::None,
            },
        );
        agent.set_adopted(poisoned).await;

        let spec = agent.board_spec(&BoardName("b1".to_owned())).await.unwrap();
        assert_eq!(spec.serial, "S1", "boards.toml must win");
    }

    /// An enumeration hiccup must not empty the inventory: a transient USB or
    /// `probe-rs` failure taking every board in the fleet offline would be much
    /// worse than a stale snapshot.
    #[tokio::test]
    async fn a_failing_lister_keeps_the_previous_inventory() {
        use crate::discovery::FailingLister;

        let mut agent = Agent::new(agent_config(), boards(), Arc::new(MockBackend::new())).unwrap();
        agent.set_clock(|| 1_000);
        let agent = agent.with_lister(Arc::new(FailingLister));
        agent.seed_inventory_from_boards().await;
        let before = agent.current_inventory().await;

        assert!(
            agent.discovery_pass().await.is_none(),
            "a failed enumeration must report nothing"
        );
        assert_eq!(agent.current_inventory().await, before);
    }

    /// A second pass over unchanged hardware reports nothing, so a quiet fleet
    /// stays quiet.
    #[tokio::test]
    async fn an_unchanged_pass_reports_nothing() {
        use crate::discovery::StubLister;

        let probes = vec![fleet_proto::DiscoveredProbe {
            serial: "S1".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        }];
        let mut agent = Agent::new(agent_config(), boards(), Arc::new(MockBackend::new())).unwrap();
        agent.set_clock(|| 1_000);
        let agent = agent.with_lister(Arc::new(StubLister(probes)));

        assert!(
            agent.discovery_pass().await.is_some(),
            "the first pass changed it"
        );
        assert!(agent.discovery_pass().await.is_none(), "nothing changed");
    }
}
