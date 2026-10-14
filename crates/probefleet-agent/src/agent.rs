//! The agent orchestrator: holds config + inventory + active sessions and
//! implements the coordinator-command handlers (architecture §4.2, §5).
//!
//! Command flow:
//! * `OpenSession` → verify the capability token locally, then splice the
//!   board's `probe-rs serve` onto the channel — **reusing** the process when
//!   one is already running for this lease, spawning otherwise.
//! * `KillSession` → drop that channel's splice. The `serve` process survives:
//!   it belongs to the lease, not the invocation.
//! * `ReleaseLease` → close the lease's channels, then run cleanup (kill the
//!   board's `serve`, power-cycle, optional erase).
//! * `PowerCycle` → kill the board's sessions, *then* power-cycle it.
//! * `QueryState` → re-report inventory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use probefleet_proto::token::AllowedOp;
use probefleet_proto::{
    BoardName, BoardRef, ChannelId, ChannelKind, CoordinatorCommand, LeaseId, NodeReport,
    PowerAction, PowerKind, ProbeInventory,
};

use crate::config::{AgentConfig, BoardSpec, BoardsConfig};
use crate::discovery::{self, ProbeLister, ProbeRsListLister};
use crate::error::{AgentError, Result};
use crate::gdb::{GdbConnection, GdbStub, ProcessGdbStub};
use crate::power::{self, PowerControl};
use crate::probers::{ProbeRsBackend, Session};
use crate::serial::{
    BusyPorts, SerialChannelCtx, SerialLister, SerialOpener, SerialportOpener, SysfsSerialLister,
};
use crate::token::Ed25519Verifier;

/// One `probe-rs serve` process and every relay channel spliced onto it.
///
/// Board-keyed rather than channel-keyed (the shape before task 3670): upstream
/// `serve` accepts connections in a loop and sequences them through its own
/// `ProbeBroker`, so many channels share one process, while two processes
/// fenced to the same probe collide in the USB driver (`errno 16`). A process
/// therefore outlives the invocation that spawned it and dies only with its
/// lease — at release, expiry, fault, or a power cycle.
struct BoardSession {
    /// The lease this process was spawned for.
    ///
    /// A channel arriving under a *different* lease means new hardware
    /// ownership: the process is torn down and respawned rather than reused, so
    /// no target state leaks between tenants.
    lease: LeaseId,
    /// The `probe-rs serve` user token written into this process's
    /// `.probe-rs.toml`. Lease-scoped, minted by the coordinator; a mismatch is
    /// treated exactly like a lease mismatch.
    serve_token: String,
    /// The running server.
    serve: Box<dyn Session>,
    /// Live channels on this board, each holding its own loopback connection
    /// until [`Agent::take_data_io`] hands it to the splice.
    channels: HashMap<ChannelId, Option<Box<dyn crate::probers::SpliceIo>>>,
}

/// An open gdb-tunnel session: a board-local `probe-rs gdb` stub whose TCP
/// stream is spliced onto the relay channel. Tracked separately from
/// [`BoardSession`] because it owns a process + connection per channel rather
/// than a shared `probe-rs serve` [`Session`], but shares the same lease/board
/// lifecycle.
struct GdbSession {
    lease: LeaseId,
    board: BoardName,
    connection: GdbConnection,
}

/// An open serial-passthrough channel (architecture §4.2, "Serial
/// passthrough"). The port itself is opened by the channel pump
/// ([`crate::serial::run_channel`]) once the client's `Open` frame names it;
/// this entry is what ties the channel to its lease/board lifecycle.
struct SerialSession {
    lease: LeaseId,
    board: BoardName,
    /// Dropping or setting this stops the pump, which closes the fd.
    stop: tokio::sync::watch::Sender<bool>,
    /// Handed to the connection layer's splice exactly once.
    ctx: Option<SerialChannelCtx>,
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
    /// Live `probe-rs serve` processes, **one per board**, each shared by every
    /// data channel open on that board (see [`BoardSession`]).
    sessions: Mutex<HashMap<BoardName, BoardSession>>,
    /// Open gdb-tunnel sessions, keyed by channel. Deliberately *not* folded
    /// into `sessions`: a gdb stub is per-channel by nature (each carries one
    /// client connection), so it has no process to share.
    gdb_sessions: Mutex<HashMap<ChannelId, GdbSession>>,
    /// Open serial-passthrough channels, keyed by channel.
    serial_sessions: Mutex<HashMap<ChannelId, SerialSession>>,
    /// Enumerates USB ttys for serial-port discovery.
    serial_lister: Arc<dyn SerialLister>,
    /// Opens serial devices (injectable for tests).
    serial_opener: Arc<dyn SerialOpener>,
    /// Device paths currently open on a serial channel.
    serial_busy: BusyPorts,
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

/// The [`BoardStatus`](probefleet_proto::BoardStatus) a **declared** board is
/// advertised as when seeding the inventory from `boards.toml` alone (no live
/// discovery yet).
///
/// The adopted counterpart is
/// [`adopted_board_status`](crate::discovery::adopted_board_status); both
/// derive the status from a [`BoardSpec`], so the id a board is reported under
/// and the id [`Agent::board_spec`] resolves cannot drift apart.
fn declared_board_status(b: &BoardSpec) -> probefleet_proto::BoardStatus {
    probefleet_proto::BoardStatus {
        board: BoardName(b.id.clone()),
        serial: b.serial.clone(),
        presence: probefleet_proto::BoardPresence::Online,
        chip: b.chip.clone(),
        model: b.model.clone(),
        tags: b.tags.clone(),
        exclusive: b.exclusive,
        power: b.power.to_power_kind(),
        adopted: false,
        // Stamped from a tty listing by `Agent::stamp_serial_ports`.
        serial_ports: Vec::new(),
    }
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
            serial_sessions: Mutex::new(HashMap::new()),
            serial_lister: Arc::new(SysfsSerialLister::default()),
            serial_opener: Arc::new(SerialportOpener),
            serial_busy: BusyPorts::default(),
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

    /// Override the USB-tty enumerator used for serial-port discovery (tests).
    #[must_use]
    pub fn with_serial_lister(mut self, lister: Arc<dyn SerialLister>) -> Self {
        self.serial_lister = lister;
        self
    }

    /// Override how serial devices are opened (tests stand a pty pair in).
    #[must_use]
    pub fn with_serial_opener(mut self, opener: Arc<dyn SerialOpener>) -> Self {
        self.serial_opener = opener;
        self
    }

    /// The serial ports of `spec`, resolved against a fresh tty listing.
    ///
    /// `vid_pid` narrows the auto-discovered match when the probe's USB ids
    /// are known; the stored spec's ids are used when non-zero.
    fn serial_ports_for(
        spec: &BoardSpec,
        vid_pid: Option<(u16, u16)>,
        ttys: &[crate::serial::UsbTty],
    ) -> Vec<crate::serial::ResolvedPort> {
        let vid_pid = vid_pid.or((spec.vid != 0 || spec.pid != 0).then_some((spec.vid, spec.pid)));
        crate::serial::resolve_ports(spec, vid_pid, ttys)
    }

    /// Stamp `serial_ports` onto every online board of `inventory`.
    fn stamp_serial_ports(
        &self,
        inventory: &mut ProbeInventory,
        adopted: &HashMap<BoardName, BoardSpec>,
        discovered: &[probefleet_proto::DiscoveredProbe],
    ) {
        let ttys = self.serial_lister.list();
        for status in &mut inventory.boards {
            if status.presence != probefleet_proto::BoardPresence::Online {
                continue;
            }
            let spec = self
                .boards
                .board(&status.board)
                .or_else(|| adopted.get(&status.board));
            let Some(spec) = spec else { continue };
            let vid_pid = discovered
                .iter()
                .find(|p| p.serial == spec.serial)
                .map(|p| (p.vid, p.pid));
            status.serial_ports = Self::serial_ports_for(spec, vid_pid, &ttys)
                .into_iter()
                .map(|p| p.info)
                .collect();
        }
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
        // Serial ports ride the same on-change report: a tty appearing or
        // vanishing changes the inventory.
        self.stamp_serial_ports(&mut inventory, &adopted, &discovered);
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
        let mut inventory = ProbeInventory {
            boards,
            unknown: Vec::new(),
        };
        self.stamp_serial_ports(&mut inventory, &HashMap::new(), &[]);
        *self.inventory.lock().await = inventory;
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
                serve_token,
                channel,
                kind,
            } => {
                self.on_open_session(lease, &board, &token, &serve_token, channel, kind)
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
        serve_token: &str,
        channel: ChannelId,
        kind: ChannelKind,
    ) -> Result<()> {
        let local = board.board_name();
        // The board must resolve: declared in `boards.toml`, or adopted from an
        // undeclared probe under `adopt = "auto"`.
        let spec = self.board_spec(&local).await?;

        // Verify the capability token locally before doing anything else. The
        // required capability depends on the channel kind: a gdb tunnel needs
        // `Gdb`; the data plane and a serial console need `Attach` (a UART is
        // no more privileged than attaching to the target).
        let required = match kind {
            ChannelKind::Data | ChannelKind::Serial => AllowedOp::Attach,
            ChannelKind::Gdb => AllowedOp::Gdb,
        };
        let now = (self.now_fn)();
        crate::token::verify_wire(&self.verifier, token_wire, lease, board, required, now)?;

        match kind {
            ChannelKind::Data => {
                self.open_data_session(lease, &local, serve_token, channel, &spec)
                    .await
            }
            ChannelKind::Gdb => self.open_gdb_session(lease, &local, channel, &spec).await,
            ChannelKind::Serial => {
                self.open_serial_session(lease, &local, channel, &spec)
                    .await
            }
        }
    }

    /// Register a serial-passthrough channel.
    ///
    /// Ports are resolved **now**, against a fresh tty listing rather than the
    /// last inventory: ttyACM numbers move after a re-enumeration or a power
    /// cycle. The device itself is opened by the pump when the client's
    /// `Open` frame names a port. Coexists with any `serve`/gdb session on
    /// the same board — flash-and-watch-the-UART is the point.
    async fn open_serial_session(
        &self,
        lease: LeaseId,
        board: &BoardName,
        channel: ChannelId,
        spec: &BoardSpec,
    ) -> Result<()> {
        let ttys = self.serial_lister.list();
        let ports = Self::serial_ports_for(spec, None, &ttys);
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let names: Vec<String> = ports.iter().map(|p| p.info.name.clone()).collect();
        self.serial_sessions.lock().await.insert(
            channel,
            SerialSession {
                lease,
                board: board.clone(),
                stop,
                ctx: Some(SerialChannelCtx {
                    ports,
                    opener: Arc::clone(&self.serial_opener),
                    busy: Arc::clone(&self.serial_busy),
                    stop: stop_rx,
                }),
            },
        );
        self.emit(NodeReport::Log {
            level: probefleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!(
                "opened serial channel {} for lease {} (ports: {})",
                channel.0,
                lease.0,
                if names.is_empty() {
                    "none".to_owned()
                } else {
                    names.join(", ")
                }
            ),
        })
        .await;
        Ok(())
    }

    /// Take the pump context of an open serial channel (once).
    pub async fn take_serial_ctx(&self, channel: ChannelId) -> Option<SerialChannelCtx> {
        self.serial_sessions
            .lock()
            .await
            .get_mut(&channel)
            .and_then(|s| s.ctx.take())
    }

    /// Forget a serial channel whose pump ended on its own. Returns whether
    /// it was still registered — i.e. whether the caller must report
    /// `SessionClosed` (an agent-initiated stop already did).
    pub async fn finish_serial(&self, channel: ChannelId) -> bool {
        self.serial_sessions.lock().await.remove(&channel).is_some()
    }

    /// Stop every serial channel without reporting (the control connection
    /// is gone, so the coordinator has dropped them already).
    pub async fn close_serial_channels(&self) {
        for (_, s) in self.serial_sessions.lock().await.drain() {
            let _ = s.stop.send(true);
        }
    }

    /// Number of open serial channels (tests).
    pub async fn serial_session_count(&self) -> usize {
        self.serial_sessions.lock().await.len()
    }

    /// Open a data-plane channel, reusing this board's `probe-rs serve` process
    /// when one is already running for the same lease.
    ///
    /// Three cases, decided under **one** `sessions` guard held across the
    /// spawn:
    ///
    /// 1. a live session for this board, same lease and same serve token →
    ///    reuse it and just connect a new loopback stream;
    /// 2. a live session under a *different* lease (or token) → kill it, report
    ///    its channels closed, and spawn afresh: a new lease is new hardware
    ///    ownership, and reusing across leases would leak target state between
    ///    tenants;
    /// 3. nothing → spawn.
    ///
    /// **A reused session whose `connect` fails is treated as dead and replaced,
    /// once.** Nothing supervises the child (`Session::wait` has no production
    /// caller), and reuse is decided on lease equality, not liveness — so a
    /// server that exited on its own (crash, OOM, probe unplugged) would
    /// otherwise fail *every* later invocation on that lease, each paying the
    /// full connect retry, until an operator released the lease. Per-channel
    /// spawning used to make that self-healing by accident; this restores the
    /// property deliberately. Exactly one retry, so a board that cannot host a
    /// server fails fast instead of respawn-looping.
    ///
    /// Holding the lock across the spawn (up to `SERVE_READY_TIMEOUT`, plus the
    /// connect) blocks [`Agent::take_data_io`] and
    /// [`Agent::active_session_count`] for that window. Accepted deliberately:
    /// it is what makes "two opens cannot race into two `serve` processes" a
    /// structural property rather than a consequence of the connection loop
    /// happening to dispatch commands serially.
    async fn open_data_session(
        &self,
        lease: LeaseId,
        board: &BoardName,
        serve_token: &str,
        channel: ChannelId,
        spec: &BoardSpec,
    ) -> Result<()> {
        let mut sessions = self.sessions.lock().await;

        // Decide from a *copied* answer rather than a live borrow: a
        // `&BoardSession` is not `Send` (its channels own `dyn SpliceIo`
        // streams, which are `Send` but not `Sync`), and holding one across the
        // spawn below would make the whole connection future non-`Send`.
        let reusable = sessions
            .get(board)
            .map(|existing| existing.lease == lease && existing.serve_token == serve_token);

        let reused = match reusable {
            Some(true) => true,
            Some(false) => {
                // Different tenant: tear the old process (and its routes) down
                // before spawning. `kill_board_session_locked` takes the map,
                // never `&self` — calling `self.on_kill_session` here would
                // re-lock `sessions` and deadlock.
                Self::kill_board_session_locked(&mut sessions, board, &self.outbox).await?;
                false
            }
            None => false,
        };

        if !reused {
            Self::spawn_board_session_locked(
                &mut sessions,
                &self.backend,
                lease,
                board,
                serve_token,
                spec,
            )
            .await?;
        }

        // Borrow only for the statement: `connect` returns an owned stream, so
        // the guard is free again for the respawn arm below.
        let connected = sessions
            .get_mut(board)
            .expect("the board session was just reused or inserted")
            .serve
            .connect()
            .await;

        let (io, outcome) = match connected {
            Ok(io) => (io, if reused { "reused" } else { "spawned" }),
            // Only a *reused* session earns a second chance: a connect failure
            // against a server we just spawned is a real spawn failure, and
            // respawning into it would loop.
            Err(e) if reused => {
                tracing::warn!(
                    board = %board.0, error = %e,
                    "the reused `probe-rs serve` is unreachable; assuming it died and respawning"
                );
                Self::kill_board_session_locked(&mut sessions, board, &self.outbox).await?;
                Self::spawn_board_session_locked(
                    &mut sessions,
                    &self.backend,
                    lease,
                    board,
                    serve_token,
                    spec,
                )
                .await?;
                let io = sessions
                    .get_mut(board)
                    .expect("the board session was just respawned")
                    .serve
                    .connect()
                    .await
                    .map_err(AgentError::Probers)?;
                (io, "respawned")
            }
            Err(e) => return Err(AgentError::Probers(e)),
        };

        sessions
            .get_mut(board)
            .expect("the board session is live")
            .channels
            .insert(channel, Some(io));
        drop(sessions);

        self.emit(NodeReport::Log {
            level: probefleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!(
                "opened session on channel {} for lease {} (serve {outcome})",
                channel.0, lease.0,
            ),
        })
        .await;
        Ok(())
    }

    /// Spawn a `probe-rs serve` for `board` and record it in the locked map.
    ///
    /// Takes the map and the backend rather than `&self` for the same reason
    /// [`Agent::kill_board_session_locked`] does: both run under the `sessions`
    /// guard, and reaching back through `self` would re-lock it.
    async fn spawn_board_session_locked(
        sessions: &mut HashMap<BoardName, BoardSession>,
        backend: &Arc<B>,
        lease: LeaseId,
        board: &BoardName,
        serve_token: &str,
        spec: &BoardSpec,
    ) -> Result<()> {
        let serve = backend
            .open(spec, serve_token)
            .await
            .map_err(AgentError::Probers)?;
        sessions.insert(
            board.clone(),
            BoardSession {
                lease,
                serve_token: serve_token.to_owned(),
                serve,
                channels: HashMap::new(),
            },
        );
        Ok(())
    }

    /// Kill the board's `probe-rs serve` process and report every channel it
    /// carried closed. Returns whether a session was present.
    ///
    /// The **data plane only**: callers wanting the board's gdb tunnels too
    /// want [`Agent::kill_board_sessions`], which owns that rule.
    ///
    /// Takes the already-locked map and the outbox directly rather than `&self`
    /// so it can run **under** the `sessions` guard: every caller holds it, and
    /// routing through `self` would re-lock and deadlock. [`Agent::emit`] locks
    /// only `outbox`, which is why passing that separately is sound.
    async fn kill_board_session_locked(
        sessions: &mut HashMap<BoardName, BoardSession>,
        board: &BoardName,
        outbox: &Mutex<Vec<NodeReport>>,
    ) -> Result<bool> {
        let Some(entry) = sessions.remove(board) else {
            return Ok(false);
        };
        entry.serve.kill().await.map_err(AgentError::Probers)?;
        let mut reports = outbox.lock().await;
        for channel in entry.channels.keys() {
            reports.push(NodeReport::SessionClosed {
                channel: *channel,
                exit_code: None,
            });
        }
        Ok(true)
    }

    /// Kill **every** session on `board` — the gdb tunnels *and* the data
    /// plane's `probe-rs serve` process, with the channels riding it.
    ///
    /// Both planes, because both hold a handle to the same physical probe: a
    /// `probe-rs gdb` stub that survives a power cycle is left holding a stale
    /// handle exactly as a surviving `serve` would. Folding the gdb half in
    /// here rather than leaving it to each caller is what makes
    /// [`Agent::kill_sessions_and_cycle`] one helper instead of a rule every
    /// power-cycling path has to remember — `on_power_cycle` is precisely the
    /// path that goes straight to the helper and would otherwise forget.
    ///
    /// The gdb half runs **first and outside** the `sessions` guard:
    /// [`Agent::on_kill_session`] takes that lock itself, so calling it under
    /// the guard would deadlock.
    ///
    /// # Errors
    ///
    /// Propagates backend termination failures.
    async fn kill_board_sessions(&self, board: &BoardName) -> Result<()> {
        for channel in self.gdb_channels_for_board(board).await {
            self.on_kill_session(channel).await?;
        }
        // Serial too: a power cycle re-enumerates the USB device, so the tty
        // fd would go stale exactly like a probe handle.
        let serial: Vec<ChannelId> = self
            .serial_sessions
            .lock()
            .await
            .iter()
            .filter(|(_, s)| &s.board == board)
            .map(|(c, _)| *c)
            .collect();
        for channel in serial {
            self.on_kill_session(channel).await?;
        }
        let mut sessions = self.sessions.lock().await;
        Self::kill_board_session_locked(&mut sessions, board, &self.outbox).await?;
        Ok(())
    }

    /// Kill this board's sessions — **both planes** — then power-cycle it.
    ///
    /// One helper for every power-cycling path (explicit power-cycle, board
    /// cleanup on release, and anything that follows) because the order is the
    /// whole point: a power cycle re-enumerates the USB device, so any process
    /// that survived it — `probe-rs serve` or a `probe-rs gdb` stub — is left
    /// holding a stale handle, the same failure class as `errno 16` reached
    /// from the other side. With board-scoped, lease-lived processes that goes
    /// from latent to guaranteed.
    async fn kill_sessions_and_cycle(&self, board: &BoardName) -> Result<()> {
        self.kill_board_sessions(board).await?;
        let power = self.power_for(board).await?;
        power.cycle().await?;
        self.emit(NodeReport::PowerEvent {
            board: board.clone(),
            action: PowerAction::Cycle,
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
            level: probefleet_proto::LogLevel::Info,
            board: Some(board.clone()),
            message: format!(
                "opened gdb tunnel on channel {} for lease {}",
                channel.0, lease.0
            ),
        })
        .await;
        Ok(())
    }

    /// Close the session on `channel` (data plane *or* gdb tunnel).
    ///
    /// For a data channel this drops **only that channel's splice**, never the
    /// `probe-rs serve` process — not even when it was the last channel on the
    /// board. Killing on last-channel-close is exactly the per-invocation
    /// respawn task 3670 removed: the process belongs to the lease, and the
    /// lease outlives one `probe-rs` run. It dies at release, expiry, fault, or
    /// a power cycle (see [`Agent::kill_board_sessions`]).
    ///
    /// The loopback socket for the dropped channel closes anyway, and that is
    /// now load-bearing: `connection::handle_inbound_command` removes
    /// `routes[channel]` after dispatching a `KillSession`, so the splice
    /// task's `from_relay.recv()` returns `None`, `splice_io` returns, and the
    /// `TcpStream` is dropped — which is what lets serve's `ProbeBroker` hand
    /// the probe to the next connection. It replaces the old invariant, "the
    /// process died and the socket EOF'd".
    async fn on_kill_session(&self, channel: ChannelId) -> Result<()> {
        let removed = {
            let mut sessions = self.sessions.lock().await;
            sessions
                .values_mut()
                .find_map(|entry| entry.channels.remove(&channel))
                .is_some()
        };
        if removed {
            self.emit(NodeReport::SessionClosed {
                channel,
                exit_code: None,
            })
            .await;
        }
        let serial = self.serial_sessions.lock().await.remove(&channel);
        if let Some(session) = serial {
            // Stops the pump, which closes the fd and drops buffered input.
            let _ = session.stop.send(true);
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

    /// Forget every data channel this agent believes is open, without killing a
    /// single `serve` process.
    ///
    /// Called by the connection loop at the **start** of every coordinator
    /// connection. A dropped control connection kills the splice tasks (their
    /// sockets close with them) but tells the agent nothing, so a reconnect
    /// would otherwise reuse a [`BoardSession`] whose `channels` map is full of
    /// ghosts and over-report [`Agent::active_session_count`]. Clearing at
    /// connection *start* rather than at teardown makes the invariant "the
    /// agent's channel set is a subset of what this connection has routed" hold
    /// however the previous connection died — including a panic.
    ///
    /// The processes deliberately survive: a lease outlives a control-plane
    /// blip, and the coordinator reopens channels onto the same lease. One whose
    /// lease really is gone is reaped when the expiry sweep sends
    /// `ReleaseLease`, so the worst case is bounded by the lease TTL rather than
    /// being a leak.
    pub async fn clear_data_channels(&self) {
        for entry in self.sessions.lock().await.values_mut() {
            entry.channels.clear();
        }
        // Serial channels are not lease-lived processes: the port is held
        // only while a channel is, so a dead connection closes them.
        self.close_serial_channels().await;
    }

    /// Release a lease: close its channels, then kill the board's `serve` and
    /// power-cycle it for cleanup.
    ///
    /// The per-channel loop is what reports `SessionClosed` for the lease's gdb
    /// tunnels (and its data channels); `cleanup_board` is what guarantees the
    /// `serve` process itself is gone. Neither subsumes the other.
    async fn on_release_lease(&self, lease: LeaseId, board: &BoardName, erase: bool) -> Result<()> {
        // Kill any session(s) tied to this lease (data plane and gdb tunnels).
        let channels = self.channels_for_lease(lease).await;
        for channel in channels {
            self.on_kill_session(channel).await?;
        }

        // Cleanup: kill the board's serve, then power-cycle.
        self.cleanup_board(board, erase).await
    }

    /// Cleanup a board: kill its `serve`, power-cycle, and optionally note
    /// erase.
    async fn cleanup_board(&self, board: &BoardName, erase: bool) -> Result<()> {
        self.kill_sessions_and_cycle(board).await?;
        if erase {
            // RESOLVE(1713): an explicit erase requires briefly attaching a
            // probe-rs session to the board and issuing `erase`. The seam is
            // here; the actual erase rides the same backend once the relay
            // splice lands. For now we record the intent.
            //
            // When it lands it inherits this function's discipline: it runs
            // *after* the kill-then-cycle above, so it never races a live
            // `serve` for the probe, and whatever session it opens must not
            // outlive it.
            self.emit(NodeReport::Log {
                level: probefleet_proto::LogLevel::Info,
                board: Some(board.clone()),
                message: "erase-on-release requested (pending backend wiring)".to_owned(),
            })
            .await;
        }
        Ok(())
    }

    /// Explicit operator power-cycle.
    ///
    /// Kills the board's sessions first: `ctl power-cycle` is an operator verb
    /// that fires **while a lease is held**, so this is not only a release-path
    /// concern. Before task 3670 this path cycled without killing anything,
    /// leaving the `serve` process holding a handle to a device that had just
    /// re-enumerated.
    async fn on_power_cycle(&self, board: &BoardName) -> Result<()> {
        self.kill_sessions_and_cycle(board).await
    }

    /// Re-report inventory upward.
    async fn on_query_state(&self) -> Result<()> {
        let inv = self.inventory.lock().await.clone();
        self.emit(NodeReport::Inventory(inv)).await;
        Ok(())
    }

    /// Quarantine a board after a fault: kill its sessions and emit a `Fault`
    /// report.
    ///
    /// Deliberately does **not** power-cycle — it resolves a controller
    /// best-effort and drops it, exactly as before task 3670. Making a fault
    /// start cycling boards is a real behaviour change, not a tidy-up.
    ///
    /// This is the one entry point outside the connection loop's serial command
    /// dispatch, so it must reach the session map only through the locked
    /// helpers ([`Agent::kill_board_sessions`], [`Agent::on_kill_session`]) and
    /// never take the `sessions` guard itself.
    ///
    /// # Errors
    ///
    /// Propagates power/backend errors.
    pub async fn fault_board(&self, board: &BoardName, reason: String) -> Result<()> {
        // Both planes, gdb tunnels included: `kill_board_sessions` owns that
        // rule, so this is not a second copy of it.
        self.kill_board_sessions(board).await?;
        // Best-effort power resolution; report the fault regardless.
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
            .values()
            .filter(|s| s.lease == lease)
            .flat_map(|s| s.channels.keys().copied())
            .collect();
        channels.extend(
            self.gdb_sessions
                .lock()
                .await
                .iter()
                .filter(|(_, s)| s.lease == lease)
                .map(|(c, _)| *c),
        );
        channels.extend(
            self.serial_sessions
                .lock()
                .await
                .iter()
                .filter(|(_, s)| s.lease == lease)
                .map(|(c, _)| *c),
        );
        channels
    }

    /// The **gdb-tunnel** channels tied to `board`.
    ///
    /// Only the gdb half: the data plane is torn down by board, not by channel
    /// ([`Agent::kill_board_sessions`]), so enumerating its channels here would
    /// invite a caller to kill them one at a time and leave the process behind.
    async fn gdb_channels_for_board(&self, board: &BoardName) -> Vec<ChannelId> {
        self.gdb_sessions
            .lock()
            .await
            .iter()
            .filter(|(_, s)| &s.board == board)
            .map(|(c, _)| *c)
            .collect()
    }

    /// Number of live data-plane **channels** (not processes; see
    /// [`Agent::serve_count`]).
    pub async fn active_session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .map(|s| s.channels.len())
            .sum()
    }

    /// Number of live `probe-rs serve` **processes**.
    ///
    /// Distinct from [`Agent::active_session_count`] since task 3670: many
    /// channels share one process, and a process outlives the channels on it.
    pub async fn serve_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Take the spliceable byte stream for an open data-plane channel, so the
    /// connection layer can byte-splice it onto the relay channel. Returns
    /// `None` if no channel is open with that id or its stream was already
    /// taken.
    pub async fn take_data_io(
        &self,
        channel: ChannelId,
    ) -> Option<Box<dyn crate::probers::SpliceIo>> {
        // Scans boards rather than keeping a second channel-keyed index: a node
        // holds a handful of boards, and one map means no cross-map invariant
        // to violate.
        self.sessions
            .lock()
            .await
            .values_mut()
            .find_map(|entry| entry.channels.get_mut(&channel))
            .and_then(Option::take)
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
    use probefleet_proto::token::{CapabilityToken, SignedToken};

    const SEED: [u8; 32] = [3u8; 32];

    /// The lease-scoped `probe-rs serve` user token, standing in for what the
    /// coordinator's `auth::serve_token` derives. The agent treats it as an
    /// opaque string it writes into `.probe-rs.toml` and compares for equality,
    /// so its shape is irrelevant here — only that two channels on one lease
    /// present the *same* one, and a different lease a different one.
    const SERVE_TOKEN: &str = "5e12e70ce11";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED)
    }

    /// The node id the coordinator handed this node at enrolment.
    ///
    /// Org-namespaced, because that is what the coordinator mints
    /// (`probefleet-coordinator/src/state.rs::node_id_for`) and returns as
    /// `TokenResponse::node_id`, which `probefleet`'s `node_setup` writes into
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
            adopt: probefleet_proto::AdoptPolicy::Declared,
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
            probefleet_proto::ids::OrgId("default".to_owned()),
            probefleet_proto::ids::NodeId(NODE_ID.to_owned()),
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

    /// Open a data channel on `b1` for `lease` with `serve_token`.
    async fn open_data(
        agent: &Agent<MockBackend>,
        lease: u64,
        channel: u64,
        serve_token: &str,
    ) -> Result<()> {
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(lease),
                board: board_ref("b1"),
                token: signed_token(lease, "b1", vec![AllowedOp::Attach], 2_000),
                serve_token: serve_token.to_owned(),
                channel: ChannelId(channel),
                kind: ChannelKind::Data,
            })
            .await
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        assert_eq!(agent.active_session_count().await, 1);
        assert_eq!(agent.serve_count().await, 1);

        agent
            .handle_command(CoordinatorCommand::ReleaseLease {
                lease: LeaseId(7),
                board: BoardName("b1".into()),
                erase: false,
            })
            .await
            .unwrap();

        assert_eq!(agent.active_session_count().await, 0);
        // No `serve` outlives its lease.
        assert_eq!(agent.serve_count().await, 0);
        assert!(backend.sessions()[0].was_killed());
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
        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        agent
            .fault_board(&BoardName("b1".into()), "probe lost".to_owned())
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 0);
        // A fault takes the whole process, not just the channel: the board is
        // quarantined, so nothing may keep driving it.
        assert_eq!(agent.serve_count().await, 0);
        assert!(backend.sessions()[0].was_killed());
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
        assert_eq!(agent.serve_count().await, 0);
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                serve_token: SERVE_TOKEN.to_owned(),
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
        // Release takes the process too, not merely the channels riding it.
        assert_eq!(agent.serve_count().await, 0);
    }

    // ---- serve reuse (task 3670, issue #512) -------------------------------

    /// **The direct `errno 16` regression test.**
    ///
    /// Two sequential invocations under one cached lease open two channels on
    /// one board. Before this, each unconditionally spawned a `probe-rs serve`,
    /// and the second one's `nusb` open failed with `interface is busy`
    /// (`errno 16`) because the first process still held the probe.
    #[tokio::test]
    async fn two_channels_on_one_board_share_one_serve() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());

        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        open_data(&agent, 7, 2, SERVE_TOKEN).await.unwrap();

        // One process...
        assert_eq!(backend.open_count(), 1, "the serve process must be reused");
        assert_eq!(agent.serve_count().await, 1);
        // ...two connections to it, one per channel...
        assert_eq!(backend.connect_count(), 2);
        assert_eq!(agent.active_session_count().await, 2);
        // ...and both channels really got a spliceable stream.
        assert!(agent.take_data_io(ChannelId(1)).await.is_some());
        assert!(agent.take_data_io(ChannelId(2)).await.is_some());
        // Taken exactly once each.
        assert!(agent.take_data_io(ChannelId(1)).await.is_none());
    }

    /// A channel under a **different lease** is new hardware ownership, so the
    /// process is torn down and respawned rather than reused — otherwise target
    /// state (and a `.probe-rs.toml` token) would leak between tenants.
    #[tokio::test]
    async fn a_channel_under_a_different_lease_respawns() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());

        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        let _ = agent.take_reports().await;
        open_data(&agent, 8, 2, "a-different-lease-token")
            .await
            .unwrap();

        assert_eq!(backend.open_count(), 2, "a new lease must respawn");
        // Still exactly one live process for the board: the old one was killed.
        assert_eq!(agent.serve_count().await, 1);
        let sessions = backend.sessions();
        assert!(sessions[0].was_killed(), "the first serve must be killed");
        assert!(!sessions[1].was_killed());
        // The first lease's channel is gone, and the coordinator was told.
        assert_eq!(agent.active_session_count().await, 1);
        let reports = agent.take_reports().await;
        assert!(
            reports.iter().any(|r| matches!(
                r,
                NodeReport::SessionClosed {
                    channel: ChannelId(1),
                    ..
                }
            )),
            "the displaced channel must be reported closed: {reports:?}"
        );
    }

    /// Killing a channel drops **only that channel's splice**. Even the last
    /// one leaves the process up: it belongs to the lease, and killing on
    /// last-channel-close is exactly the per-invocation respawn that caused
    /// `errno 16`.
    #[tokio::test]
    async fn killing_channels_leaves_the_serve_running() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        open_data(&agent, 7, 2, SERVE_TOKEN).await.unwrap();

        agent
            .handle_command(CoordinatorCommand::KillSession {
                channel: ChannelId(1),
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 1);
        assert_eq!(agent.serve_count().await, 1);

        // The *last* channel too: still no kill.
        agent
            .handle_command(CoordinatorCommand::KillSession {
                channel: ChannelId(2),
            })
            .await
            .unwrap();
        assert_eq!(agent.active_session_count().await, 0);
        assert_eq!(agent.serve_count().await, 1);
        assert!(!backend.sessions()[0].was_killed());

        // And the next invocation reuses it rather than respawning.
        open_data(&agent, 7, 3, SERVE_TOKEN).await.unwrap();
        assert_eq!(backend.open_count(), 1);
    }

    /// A power cycle re-enumerates the USB device, so the board's `serve` must
    /// die **before** the cycle or it is left holding a stale handle.
    ///
    /// Ordering, not membership: `ctl power-cycle` used to cycle without
    /// killing anything at all, which a set-based assertion would not
    /// distinguish from killing afterwards.
    #[tokio::test(start_paused = true)]
    async fn power_cycle_kills_sessions_before_cycling() {
        let log: crate::probers::mock::EventLog =
            Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let backend = Arc::new(MockBackend::with_log(Arc::clone(&log)));
        let mut agent = Agent::new(agent_config(), boards(), backend.clone()).unwrap();
        agent.set_clock(|| 1_000);
        agent.set_gdb_stub(Arc::new(crate::gdb::mock::MockGdbStub::new()));
        let power_log = Arc::clone(&log);
        agent.set_power_factory(Box::new(move |_| {
            Box::new(RecordingPower(Arc::clone(&power_log)))
        }));

        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        agent
            .handle_command(CoordinatorCommand::PowerCycle {
                board: BoardName("b1".into()),
            })
            .await
            .unwrap();

        assert_eq!(
            *log.lock().unwrap(),
            vec!["spawn:b1", "kill:b1", "cycle"],
            "the board's serve must die before the probe re-enumerates"
        );
        assert_eq!(agent.serve_count().await, 0);
    }

    /// A power cycle takes the board's **gdb** stub down too, and before the
    /// cycle.
    ///
    /// Both planes hold a handle to the same physical probe, so a `probe-rs
    /// gdb` surviving a re-enumeration is the identical stale-handle bug as a
    /// surviving `serve`. `on_power_cycle` is the path that goes straight to
    /// the shared helper, so it is the one that would silently miss a plane the
    /// helper forgot.
    #[tokio::test(start_paused = true)]
    async fn power_cycle_kills_the_gdb_stub_too() {
        let log: crate::probers::mock::EventLog =
            Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let backend = Arc::new(MockBackend::with_log(Arc::clone(&log)));
        let mut agent = Agent::new(agent_config(), boards(), backend.clone()).unwrap();
        agent.set_clock(|| 1_000);
        agent.set_gdb_stub(Arc::new(crate::gdb::mock::MockGdbStub::new()));
        let power_log = Arc::clone(&log);
        agent.set_power_factory(Box::new(move |_| {
            Box::new(RecordingPower(Arc::clone(&power_log)))
        }));

        // Both planes live on the board at once.
        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token: signed_token(7, "b1", vec![AllowedOp::Gdb], 2_000),
                serve_token: SERVE_TOKEN.to_owned(),
                channel: ChannelId(2),
                kind: ChannelKind::Gdb,
            })
            .await
            .unwrap();
        assert_eq!(agent.gdb_session_count().await, 1);

        agent
            .handle_command(CoordinatorCommand::PowerCycle {
                board: BoardName("b1".into()),
            })
            .await
            .unwrap();

        assert_eq!(
            agent.gdb_session_count().await,
            0,
            "the gdb stub must not survive the re-enumeration either"
        );
        assert_eq!(agent.serve_count().await, 0);
        // The gdb stub is killed through `on_kill_session`, which the mock does
        // not log, so ordering is asserted on what the log does see: the serve
        // still dies before the cycle, and the cycle is last.
        assert_eq!(*log.lock().unwrap(), vec!["spawn:b1", "kill:b1", "cycle"]);
        // The gdb teardown is reported upward, and it happened before the
        // PowerEvent — the ordering that matters, in the reports themselves.
        let reports = agent.take_reports().await;
        let closed = reports
            .iter()
            .position(|r| matches!(r, NodeReport::SessionClosed { channel, .. } if *channel == ChannelId(2)))
            .expect("the gdb channel must be reported closed");
        let cycled = reports
            .iter()
            .position(|r| matches!(r, NodeReport::PowerEvent { .. }))
            .expect("the board must be cycled");
        assert!(
            closed < cycled,
            "the gdb tunnel must be torn down before the cycle: {reports:?}"
        );
    }

    /// A `probe-rs serve` that exits on its own is replaced on the next
    /// invocation, rather than stranding the lease.
    ///
    /// Nothing supervises the child and reuse is decided on lease equality, not
    /// liveness, so without this a crashed server would fail *every* later
    /// invocation on that lease — each paying the full connect retry — until an
    /// operator released it. Per-channel spawning made that self-healing by
    /// accident; this is the deliberate replacement.
    #[tokio::test]
    async fn a_serve_that_died_on_its_own_is_respawned() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());

        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        assert_eq!(backend.open_count(), 1);

        // The server dies between invocations: its socket stops answering.
        backend.sessions()[0].fail_next_connects(1);

        open_data(&agent, 7, 2, SERVE_TOKEN).await.unwrap();

        assert_eq!(
            backend.open_count(),
            2,
            "an unreachable reused serve must be replaced, not reused again"
        );
        assert_eq!(agent.serve_count().await, 1);
        assert!(
            agent.take_data_io(ChannelId(2)).await.is_some(),
            "and the channel really gets a stream off the new process"
        );
        // The dead one is reaped rather than left in the map.
        assert!(backend.sessions()[0].was_killed());
    }

    /// The respawn is **once**, not a loop: a board that genuinely cannot host
    /// a server fails fast with the backend's own error.
    #[tokio::test]
    async fn a_serve_that_cannot_be_reached_at_all_fails_rather_than_looping() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());

        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        // Both the reused session's connect and the respawned one's fail.
        backend.sessions()[0].fail_next_connects(1);
        backend.set_fail_connect(true);

        let err = open_data(&agent, 7, 2, SERVE_TOKEN).await.unwrap_err();
        assert!(matches!(err, AgentError::Probers(_)), "got {err:?}");
        // Exactly one respawn attempt was made.
        assert_eq!(backend.open_count(), 2);
    }

    /// A `PowerControl` that records the cycle into the shared event log, so
    /// kill-then-cycle ordering can be asserted against the backend's events.
    struct RecordingPower(crate::probers::mock::EventLog);

    #[async_trait::async_trait]
    impl crate::power::PowerControl for RecordingPower {
        async fn cycle(&self) -> std::result::Result<(), crate::power::PowerError> {
            self.0.lock().unwrap().push("cycle".to_owned());
            Ok(())
        }
        async fn off(&self) -> std::result::Result<(), crate::power::PowerError> {
            self.0.lock().unwrap().push("off".to_owned());
            Ok(())
        }
        async fn on(&self) -> std::result::Result<(), crate::power::PowerError> {
            self.0.lock().unwrap().push("on".to_owned());
            Ok(())
        }
        fn label(&self) -> String {
            "recording".to_owned()
        }
    }

    /// A reconnect must not inherit the previous connection's channels: their
    /// splice tasks died with it, but the `serve` process legitimately survives
    /// (a lease outlives a control-plane blip), so a reused `BoardSession`
    /// would otherwise report ghosts forever.
    #[tokio::test]
    async fn clearing_data_channels_forgets_channels_but_keeps_the_serve() {
        let backend = Arc::new(MockBackend::new());
        let agent = make_agent(backend.clone());
        open_data(&agent, 7, 1, SERVE_TOKEN).await.unwrap();
        assert_eq!(agent.active_session_count().await, 1);

        agent.clear_data_channels().await;

        assert_eq!(agent.active_session_count().await, 0);
        assert_eq!(agent.serve_count().await, 1);
        assert!(!backend.sessions()[0].was_killed());
        // The coordinator reopens onto the same lease, and finds the process.
        open_data(&agent, 7, 5, SERVE_TOKEN).await.unwrap();
        assert_eq!(backend.open_count(), 1);
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
        config.adopt = probefleet_proto::AdoptPolicy::Auto;
        // A probe nobody declared: `boards()` knows only S1.
        let probe = probefleet_proto::DiscoveredProbe {
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
                serve_token: SERVE_TOKEN.to_owned(),
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
        config.adopt = probefleet_proto::AdoptPolicy::Auto;
        let probe = probefleet_proto::DiscoveredProbe {
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
        assert_eq!(status.presence, probefleet_proto::BoardPresence::Offline);
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

        let probe = probefleet_proto::DiscoveredProbe {
            serial: "ZZZ".to_owned(),
            vid: 0x1366,
            pid: 0x1015,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        };
        let mut config = agent_config();
        config.adopt = probefleet_proto::AdoptPolicy::Auto;
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
            .find(|b| b.adopted && b.presence == probefleet_proto::BoardPresence::Online)
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
        config.adopt = probefleet_proto::AdoptPolicy::Declared;
        let probe = probefleet_proto::DiscoveredProbe {
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
                serve_token: SERVE_TOKEN.to_owned(),
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
                uart: Vec::new(),
                uart_discover: true,
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

        let probes = vec![probefleet_proto::DiscoveredProbe {
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

    // ---- serial passthrough ---------------------------------------------

    fn serial_tty() -> crate::serial::UsbTty {
        crate::serial::UsbTty {
            tty: "ttyACM0".to_owned(),
            path: std::path::PathBuf::from("/dev/ttyACM0"),
            vid: 0x1366,
            pid: 0x1015,
            usb_serial: Some("S1".to_owned()),
            usb_device_path: std::path::PathBuf::from("/sys/devices/x"),
            interface: Some(2),
        }
    }

    fn serial_agent() -> Agent<MockBackend> {
        let lister = crate::serial::StaticSerialLister::default();
        lister.0.lock().unwrap().push(serial_tty());
        make_agent(Arc::new(MockBackend::new())).with_serial_lister(Arc::new(lister))
    }

    async fn open_serial(
        agent: &Agent<MockBackend>,
        lease: u64,
        channel: u64,
        ops: Vec<AllowedOp>,
    ) -> Result<()> {
        agent
            .handle_command(CoordinatorCommand::OpenSession {
                lease: LeaseId(lease),
                board: board_ref("b1"),
                token: signed_token(lease, "b1", ops, 2_000),
                serve_token: SERVE_TOKEN.to_owned(),
                channel: ChannelId(channel),
                kind: ChannelKind::Serial,
            })
            .await
    }

    #[tokio::test]
    async fn serial_ports_are_stamped_onto_the_inventory() {
        let agent = serial_agent();
        agent.seed_inventory_from_boards().await;
        let inv = agent.current_inventory().await;
        let ports = &inv.boards[0].serial_ports;
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "if2");
        assert_eq!(ports[0].device, "ttyACM0");
    }

    #[tokio::test]
    async fn serial_channel_needs_attach() {
        let agent = serial_agent();
        let err = open_serial(&agent, 7, 1, vec![AllowedOp::Gdb])
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Token(_)));
        assert_eq!(agent.serial_session_count().await, 0);
        open_serial(&agent, 7, 1, vec![AllowedOp::Attach])
            .await
            .unwrap();
        assert_eq!(agent.serial_session_count().await, 1);
        // The serial channel spawns no `probe-rs serve`.
        assert_eq!(agent.serve_count().await, 0);
    }

    #[tokio::test]
    async fn release_kill_and_power_cycle_stop_serial_channels() {
        let agent = serial_agent();
        open_serial(&agent, 7, 1, vec![AllowedOp::Attach])
            .await
            .unwrap();
        let mut ctx = agent.take_serial_ctx(ChannelId(1)).await.unwrap();
        assert!(
            agent.take_serial_ctx(ChannelId(1)).await.is_none(),
            "taken once"
        );
        agent
            .handle_command(CoordinatorCommand::ReleaseLease {
                lease: LeaseId(7),
                board: BoardName("b1".into()),
                erase: false,
            })
            .await
            .unwrap();
        assert_eq!(agent.serial_session_count().await, 0);
        // The pump's stop signal fired (or its sender is gone).
        assert!(*ctx.stop.borrow_and_update() || ctx.stop.has_changed().is_err());
        assert!(agent.take_reports().await.iter().any(
            |r| matches!(r, NodeReport::SessionClosed { channel, .. } if *channel == ChannelId(1))
        ));
        // An agent stop means the pump must not report again.
        assert!(!agent.finish_serial(ChannelId(1)).await);

        open_serial(&agent, 8, 2, vec![AllowedOp::Attach])
            .await
            .unwrap();
        agent
            .handle_command(CoordinatorCommand::KillSession {
                channel: ChannelId(2),
            })
            .await
            .unwrap();
        assert_eq!(agent.serial_session_count().await, 0);

        open_serial(&agent, 8, 3, vec![AllowedOp::Attach])
            .await
            .unwrap();
        agent
            .handle_command(CoordinatorCommand::PowerCycle {
                board: BoardName("b1".into()),
            })
            .await
            .unwrap();
        assert_eq!(agent.serial_session_count().await, 0);

        open_serial(&agent, 8, 4, vec![AllowedOp::Attach])
            .await
            .unwrap();
        agent.clear_data_channels().await;
        assert_eq!(
            agent.serial_session_count().await,
            0,
            "a dropped connection closes serial"
        );
    }
}
