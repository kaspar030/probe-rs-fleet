//! probe-rs `serve` lifecycle + byte-proxy (architecture §4.2).
//!
//! Decided model: the agent runs **one `probe-rs serve` per board** listening
//! on a loopback **TCP** port, each locked to its physical probe via a per-board
//! user with `ProbeAccess::Allow(["vid:pid:serial"])` + a lease-scoped token.
//! `probe-rs serve` (0.32) speaks **WebSocket** at route `/worker`; the agent
//! then **byte-splices** the raw TCP stream (the bytes of that WebSocket
//! connection) between serve's port and the coordinator-relayed data channel —
//! *zero* probe-rs / WebSocket parsing.
//!
//! The server is **reused** across a holder's many invocations (matching
//! time-based sharing, §6) and recycled on board release, fault or power-cycle.
//! That is why the seam is split in two: [`ProbeRsBackend::open`] spawns a
//! process (once per board per lease) and [`Session::connect`] opens one
//! loopback connection per relay channel. Upstream `serve` accepts connections
//! in a loop and sequences them through a shared `ProbeBroker`; two *processes*
//! fenced to the same probe cannot share that broker and collide in the USB
//! driver instead (`nusb` `errno 16`).
//!
//! `probe-rs serve` 0.32 takes **no** `--config`, `--probe` or `--chip`: its
//! `ServerConfig` is loaded via **Figment** from a `.probe-rs.{toml,json,yaml}`
//! file searched in cwd → exe dir → home, and the connecting client selects
//! probe + chip in-band over the WebSocket. So the agent spawns serve with a
//! per-board `current_dir` containing a generated `.probe-rs.toml`; isolation is
//! the per-board `ProbeAccess::Allow(["vid:pid:serial"])` fence under that config's
//! `[server]` table.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::BoardSpec;
use crate::discovery::{enrich_boards_with_discovery, ProbeLister, ProbeRsListLister};

/// A byte stream the agent splices onto a relay data channel: the connected
/// TCP transport to a board's `probe-rs serve` WebSocket port (or, in tests, an
/// in-memory duplex). Object-safe so the concrete transport (TCP socket vs.
/// mock) is hidden behind the [`Session`] trait.
pub trait SpliceIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SpliceIo for T {}

/// Where a board's `probe-rs serve` instance listens, and the config that
/// pins it to a single probe. This is the input the real process backend turns
/// into a spawned `probe-rs serve` + its `.probe-rs.toml` Figment config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSpec {
    /// Board id (for logging / lookup).
    pub board: String,
    /// The probe serial this server is locked to (part of the canonical
    /// `vid:pid:serial` `ProbeAccess::Allow` selector).
    pub serial: String,
    /// USB vendor id of the bound probe (canonical allow selector). Sourced
    /// from runtime USB discovery via [`BoardSpec`].
    pub vid: u16,
    /// USB product id of the bound probe (canonical allow selector).
    pub pid: u16,
    /// Loopback address `probe-rs serve` binds (`[server].address`).
    pub address: String,
    /// Loopback TCP port `probe-rs serve` binds (`[server].port`). Allocated
    /// per-board (ephemeral) so multiple boards never collide on serve's
    /// default `3000`.
    pub port: u16,
}

impl ServeSpec {
    /// Derive a serve spec for `board`, allocating an ephemeral loopback port.
    ///
    /// The port is obtained by binding `127.0.0.1:0`, reading the assigned
    /// port, then dropping the listener so `probe-rs serve` can bind it. There
    /// is a tiny bind/close race window; the connect-retry loop in
    /// [`connect_serve_tcp`] tolerates it.
    ///
    /// # Errors
    ///
    /// Returns an error string if an ephemeral port could not be allocated.
    pub fn for_board(board: &BoardSpec) -> Result<Self, String> {
        let port = alloc_ephemeral_port()?;
        Ok(Self {
            board: board.id.clone(),
            serial: board.serial.clone(),
            vid: board.vid,
            pid: board.pid,
            address: "127.0.0.1".to_owned(),
            port,
        })
    }

    /// The loopback `host:port` `probe-rs serve` listens on.
    #[must_use]
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    /// Render the `probe-rs serve` Figment (`.probe-rs.toml`) config that locks
    /// the server to this board's probe over its loopback TCP port.
    ///
    /// Shape (probe-rs 0.32, `Config { server: ServerConfig }` with
    /// `#[serde(deny_unknown_fields)]`): a `[server]` table carrying
    /// `address`/`port` and one `[[server.users]]` with a required `name`, the
    /// per-board `token`, and `access = { allow = ["<serial>"] }`
    /// (`ProbeAccess::Allow`).
    ///
    /// `serve_token` is the **lease-scoped** `probe-rs serve` user token the
    /// connecting client must present, minted by the coordinator and carried to
    /// both ends (`OpenSession { serve_token }` / `ChannelOpened
    /// { serve_token }`), so the sidecar's `PROBE_RS_REMOTE_TOKEN` matches
    /// verbatim. It is deliberately *not* the per-channel capability token: a
    /// reused server reads this config exactly once at startup, so a
    /// per-channel value would force a respawn per invocation.
    #[must_use]
    pub fn render_server_config(&self, serve_token: &str) -> String {
        format!(
            "[server]\n\
             address = \"{address}\"\n\
             port = {port}\n\
             \n\
             [[server.users]]\n\
             name = \"fleet\"\n\
             token = \"{token}\"\n\
             access = {{ allow = [\"{vid:04x}:{pid:04x}:{serial}\"] }}\n",
            address = self.address,
            port = self.port,
            token = serve_token,
            vid = self.vid,
            pid = self.pid,
            serial = self.serial,
        )
    }
}

/// Allocate an ephemeral loopback TCP port by binding `127.0.0.1:0` and
/// immediately releasing it, returning the kernel-assigned port number.
fn alloc_ephemeral_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("allocating ephemeral serve port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("reading ephemeral serve port: {e}"))?
        .port();
    Ok(port)
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// The `probe-rs serve` process exited on its own with this code.
    Exited(i32),
    /// The agent killed the process (lease release / fault / explicit kill).
    Killed,
}

/// A live probe-rs session: a running `probe-rs serve` for one board, shared by
/// every channel spliced onto it.
///
/// One process per **board** (per lease), not per channel: `probe-rs serve`
/// accepts connections in a loop and sequences them through its own
/// `ProbeBroker`, whereas two OS processes fenced to the same probe collide in
/// the USB driver (`errno 16`). [`Session::connect`] is therefore called once
/// per channel; [`ProbeRsBackend::open`] once per board.
#[async_trait]
pub trait Session: Send + Sync {
    /// The board this session serves.
    fn board(&self) -> &str;

    /// Open a **fresh** spliceable byte stream to this session's server.
    ///
    /// Called once per relay channel. The first call hands back the connection
    /// [`ProbeRsBackend::open`] already established as its readiness proof (so
    /// the first channel behaves exactly as it did when there was one
    /// connection per process); later calls dial the recorded loopback address
    /// again.
    ///
    /// # Errors
    ///
    /// Returns an error string if the server could not be reached.
    async fn connect(&self) -> Result<Box<dyn SpliceIo>, String>;

    /// Kill the session: terminate the process and stop the splice.
    ///
    /// # Errors
    ///
    /// Returns an error string if termination fails.
    async fn kill(&self) -> Result<(), String>;

    /// Await the session's exit, returning how it ended.
    async fn wait(&self) -> SessionExit;
}

/// Spawns and manages `probe-rs serve` instances per board.
///
/// Abstracted as a trait so the agent's lifecycle state machine is unit-tested
/// with a mock backend; the real [`ProcessBackend`] spawns processes.
#[async_trait]
pub trait ProbeRsBackend: Send + Sync {
    /// Open a session for `board`, locking serve to `serve_token` (the
    /// lease-scoped `probe-rs serve` user token the coordinator minted, written
    /// into the per-board `.probe-rs.toml` user so it matches the client's
    /// `PROBE_RS_REMOTE_TOKEN`). The returned [`Session`] owns the process;
    /// each relay channel then calls [`Session::connect`] for its own stream.
    ///
    /// Called **once per board per lease**, not once per channel.
    ///
    /// # Errors
    ///
    /// Returns an error string if the server could not be started.
    async fn open(&self, board: &BoardSpec, serve_token: &str) -> Result<Box<dyn Session>, String>;
}

/// The real, process-spawning backend.
///
/// Spawns `probe-rs serve` per board with a generated `.probe-rs.toml` Figment
/// config in a per-board `current_dir`, then byte-splices serve's loopback TCP
/// stream (the bytes of its `/worker` WebSocket) onto the relay.
pub struct ProcessBackend {
    /// Directory under which per-board working dirs and config files are written.
    runtime_dir: PathBuf,
    /// The `probe-rs` binary to invoke.
    program: String,
    /// Enumerates attached probes so each board's USB vid/pid can be resolved at
    /// spawn time (the serve config's allow entry needs the canonical
    /// `vid:pid:serial` selector). Defaults to a real `probe-rs list` shell-out;
    /// injectable for tests.
    lister: Arc<dyn ProbeLister>,
}

impl std::fmt::Debug for ProcessBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessBackend")
            .field("runtime_dir", &self.runtime_dir)
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

impl ProcessBackend {
    /// Build a process backend writing per-board working dirs under `runtime_dir`.
    ///
    /// Uses a real `probe-rs list` enumerator (the same `probe-rs` binary used
    /// for `serve`) to resolve probe vid/pid at spawn time.
    #[must_use]
    pub fn new(runtime_dir: PathBuf) -> Self {
        Self {
            runtime_dir,
            program: "probe-rs".to_owned(),
            lister: Arc::new(ProbeRsListLister::default()),
        }
    }

    /// Override the `probe-rs` binary path (e.g. for tests / non-default
    /// install). Also re-points the probe enumerator at the same binary.
    #[must_use]
    pub fn with_program(mut self, program: String) -> Self {
        self.program.clone_from(&program);
        self.lister = Arc::new(ProbeRsListLister::new(program));
        self
    }

    /// Override the probe enumerator (tests inject a mock so spawn-time vid/pid
    /// resolution is exercised without real hardware).
    #[must_use]
    pub fn with_lister(mut self, lister: Arc<dyn ProbeLister>) -> Self {
        self.lister = lister;
        self
    }

    /// The serve spec this backend would use for `board`, with the probe's
    /// USB vid/pid resolved from live enumeration.
    ///
    /// # Errors
    ///
    /// Returns an error string if an ephemeral port could not be allocated, if
    /// probe enumeration fails, if the board's serial is not found among the
    /// attached probes (so we never render an unmatchable `0000:0000:<serial>`
    /// allow entry), or if the matched probe is present but **inaccessible**
    /// (probe-rs 0.32 cannot open it — see [`DiscoveredProbe::inaccessible`]),
    /// in which case spawning `serve` would only fail later and less legibly.
    pub async fn serve_spec(&self, board: &BoardSpec) -> Result<ServeSpec, String> {
        let enriched = self.resolve_board_ids(board).await?;
        ServeSpec::for_board(&enriched)
    }

    /// Stamp `board`'s USB vid/pid from a fresh `probe-rs list` enumeration,
    /// matched by serial. Errors loudly if the board's probe is not present,
    /// is present but inaccessible, or the discovered vid/pid are unusable
    /// (zero), since rendering `0000:0000:<serial>` would silently no-op every
    /// remote attach.
    async fn resolve_board_ids(&self, board: &BoardSpec) -> Result<BoardSpec, String> {
        let discovered = self.lister.list_probes().await?;
        // Refuse a probe probe-rs 0.32 reported as `(inaccessible)`: `serve`
        // would start but never be able to open the probe. Fail here, naming
        // the likely cause, rather than at attach time.
        if let Some(p) = discovered.iter().find(|p| p.serial == board.serial) {
            if p.inaccessible {
                return Err(format!(
                    "probe with serial {} is attached but inaccessible to probe-rs \
                     (`probe-rs list` marks it `(inaccessible)`); check USB device-node \
                     permissions (udev rule / group membership) for this user",
                    board.serial,
                ));
            }
        }
        let mut boards = crate::config::BoardsConfig {
            boards: vec![board.clone()],
        };
        enrich_boards_with_discovery(&mut boards, &discovered);
        let enriched = boards.boards.remove(0);
        if enriched.vid == 0 && enriched.pid == 0 {
            return Err(format!(
                "probe with serial {} not found among {} attached probe(s); \
                 cannot render canonical vid:pid:serial allow entry (refusing to \
                 emit unmatchable 0000:0000:{})",
                board.serial,
                discovered.len(),
                board.serial,
            ));
        }
        Ok(enriched)
    }
}

/// Time to wait for a freshly-spawned `probe-rs serve` to start listening.
const SERVE_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Poll interval while retry-connecting to the serve TCP port.
const SERVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// A live `probe-rs serve` session: a running child process plus the loopback
/// address it listens on, which every channel on this board dials for its own
/// stream.
struct ProcessSession {
    board: String,
    child: tokio::sync::Mutex<tokio::process::Child>,
    /// `host:port` the server listens on, redialled per channel.
    socket_addr: String,
    /// The connection `open` established as its readiness proof, handed to the
    /// first channel so the common case costs no extra connect (and leaves no
    /// stray half-open connection in serve's log).
    first_io: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    killed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Session for ProcessSession {
    fn board(&self) -> &str {
        &self.board
    }

    async fn connect(&self) -> Result<Box<dyn SpliceIo>, String> {
        if let Some(stream) = self.first_io.lock().await.take() {
            return Ok(Box::new(stream) as Box<dyn SpliceIo>);
        }
        let stream = connect_serve_tcp(&self.socket_addr).await?;
        Ok(Box::new(stream) as Box<dyn SpliceIo>)
    }

    async fn kill(&self) -> Result<(), String> {
        self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
        Ok(())
    }

    async fn wait(&self) -> SessionExit {
        let mut child = self.child.lock().await;
        match child.wait().await {
            Ok(status) => {
                if self.killed.load(std::sync::atomic::Ordering::SeqCst) {
                    SessionExit::Killed
                } else {
                    SessionExit::Exited(status.code().unwrap_or(-1))
                }
            }
            Err(_) => SessionExit::Killed,
        }
    }
}

#[async_trait]
impl ProbeRsBackend for ProcessBackend {
    async fn open(&self, board: &BoardSpec, serve_token: &str) -> Result<Box<dyn Session>, String> {
        let spec = self.serve_spec(board).await?;

        // 1. Create a per-board working dir and write `.probe-rs.toml` into it
        //    (Figment searches cwd for this filename). The config locks the
        //    server to this board's probe via `ProbeAccess::Allow([serial])`
        //    and pins its loopback port.
        let work_dir = self.runtime_dir.join(format!("serve-{}", spec.board));
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("creating serve work dir {}: {e}", work_dir.display()))?;
        let config_path = work_dir.join(".probe-rs.toml");
        tokio::fs::write(&config_path, spec.render_server_config(serve_token))
            .await
            .map_err(|e| format!("writing serve config {}: {e}", config_path.display()))?;

        // 2. Spawn `probe-rs serve` with no `--config`/`--probe`/`--chip`: its
        //    `ServerConfig` is loaded via Figment from the `.probe-rs.toml` in
        //    `current_dir`, and the client selects probe + chip in-band over
        //    the WebSocket. Isolation is the `ProbeAccess` fence in the config.
        let child = tokio::process::Command::new(&self.program)
            .arg("serve")
            .current_dir(&work_dir)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                format!(
                    "failed to spawn `{} serve` for board {}: {e}",
                    self.program, spec.board
                )
            })?;

        // 3. Retry-connect to serve's loopback TCP port until it is listening.
        let io = match connect_serve_tcp(&spec.socket_addr()).await {
            Ok(stream) => stream,
            Err(e) => {
                // Tear the half-started process down before surfacing the error.
                let mut child = child;
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(e);
            }
        };

        Ok(Box::new(ProcessSession {
            board: spec.board.clone(),
            child: tokio::sync::Mutex::new(child),
            socket_addr: spec.socket_addr(),
            first_io: tokio::sync::Mutex::new(Some(io)),
            killed: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}

/// Retry-connect to a `probe-rs serve` loopback TCP port until it is listening
/// or the ready timeout elapses. Sets `TCP_NODELAY` on the established stream.
async fn connect_serve_tcp(addr: &str) -> Result<tokio::net::TcpStream, String> {
    let deadline = tokio::time::Instant::now() + SERVE_READY_TIMEOUT;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "`probe-rs serve` port {addr} never became reachable: {e}"
                    ));
                }
                tokio::time::sleep(SERVE_POLL_INTERVAL).await;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A mock backend + session for unit-testing the agent state machine.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use super::{ProbeRsBackend, Session, SessionExit, SpliceIo};
    use crate::config::BoardSpec;
    use async_trait::async_trait;
    use tokio::sync::Notify;

    /// A shared, ordered log of backend/session lifecycle events.
    ///
    /// Ordering is the point: the power-cycle tests assert that a board's serve
    /// was killed *before* the board was cycled, which set membership cannot
    /// distinguish from the bug.
    pub type EventLog = Arc<StdMutex<Vec<String>>>;

    /// A mock session whose exit can be driven by the test.
    pub struct MockSession {
        board: String,
        killed: Arc<AtomicBool>,
        exit_notify: Arc<Notify>,
        exit: Arc<std::sync::Mutex<Option<SessionExit>>>,
        /// Peer halves of the duplexes handed out by `connect`, in order, for
        /// the test to drive as if it were `probe-rs serve`.
        peers: tokio::sync::Mutex<Vec<tokio::io::DuplexStream>>,
        /// How many channels have connected to this session.
        connects: AtomicUsize,
        /// How many of the next `connect` calls must fail, emulating a server
        /// that exited on its own (crash, OOM, probe unplugged): the socket is
        /// simply not there any more.
        fail_connects: AtomicUsize,
        log: Option<EventLog>,
    }

    impl MockSession {
        #[must_use]
        pub fn new(board: String) -> Self {
            Self {
                board,
                killed: Arc::new(AtomicBool::new(false)),
                exit_notify: Arc::new(Notify::new()),
                exit: Arc::new(std::sync::Mutex::new(None)),
                peers: tokio::sync::Mutex::new(Vec::new()),
                connects: AtomicUsize::new(0),
                fail_connects: AtomicUsize::new(0),
                log: None,
            }
        }

        /// A mock session that appends its lifecycle events to `log`.
        #[must_use]
        pub fn with_log(board: String, log: EventLog) -> Self {
            let mut s = Self::new(board);
            s.log = Some(log);
            s
        }

        /// Build a mock session and eagerly connect one channel, returning the
        /// peer half the test drives to emulate `probe-rs serve`.
        ///
        /// A thin wrapper over [`MockSession::connect`] for tests that want the
        /// peer before the agent asks for its stream.
        #[allow(dead_code)]
        pub async fn with_io(board: String) -> (Self, tokio::io::DuplexStream) {
            let s = Self::new(board);
            let _ = s.connect().await.expect("mock connect never fails");
            let peer = s.take_peer().await.expect("connect pushes a peer");
            (s, peer)
        }

        /// Take the oldest not-yet-taken peer half.
        pub async fn take_peer(&self) -> Option<tokio::io::DuplexStream> {
            let mut peers = self.peers.lock().await;
            if peers.is_empty() {
                None
            } else {
                Some(peers.remove(0))
            }
        }

        /// How many channels have connected to this session.
        #[must_use]
        pub fn connect_count(&self) -> usize {
            self.connects.load(Ordering::SeqCst)
        }

        /// Make the next `n` `connect` calls fail, as a `probe-rs serve` that
        /// died on its own would.
        pub fn fail_next_connects(&self, n: usize) {
            self.fail_connects.store(n, Ordering::SeqCst);
        }

        #[must_use]
        pub fn was_killed(&self) -> bool {
            self.killed.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Session for MockSession {
        fn board(&self) -> &str {
            &self.board
        }

        async fn connect(&self) -> Result<Box<dyn SpliceIo>, String> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            if self
                .fail_connects
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    // `then_some(n - 1)` would underflow: the argument is
                    // evaluated eagerly, including when `n == 0`.
                    if n > 0 {
                        Some(n - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return Err("mock serve is not listening".to_owned());
            }
            let (agent_side, peer) = tokio::io::duplex(4096);
            self.peers.lock().await.push(peer);
            Ok(Box::new(agent_side) as Box<dyn SpliceIo>)
        }

        async fn kill(&self) -> Result<(), String> {
            self.killed.store(true, Ordering::SeqCst);
            if let Some(log) = &self.log {
                log.lock().unwrap().push(format!("kill:{}", self.board));
            }
            *self.exit.lock().unwrap() = Some(SessionExit::Killed);
            self.exit_notify.notify_waiters();
            Ok(())
        }

        async fn wait(&self) -> SessionExit {
            loop {
                if let Some(e) = *self.exit.lock().unwrap() {
                    return e;
                }
                self.exit_notify.notified().await;
            }
        }
    }

    /// A mock backend that hands out [`MockSession`]s and counts opens. Can be
    /// configured to fail `open`.
    #[derive(Default)]
    pub struct MockBackend {
        opens: AtomicUsize,
        fail: AtomicBool,
        /// Sessions handed out from now on refuse every `connect`, emulating a
        /// board whose server cannot be reached at all.
        fail_connect: AtomicBool,
        log: Option<EventLog>,
        /// Every session handed out, so a test can assert on one after the
        /// agent has taken ownership of it.
        sessions: StdMutex<Vec<Arc<MockSession>>>,
    }

    impl MockBackend {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// A backend whose sessions append their lifecycle events to `log`.
        #[must_use]
        pub fn with_log(log: EventLog) -> Self {
            Self {
                log: Some(log),
                ..Self::default()
            }
        }

        #[allow(dead_code)]
        pub fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }

        /// Make every session handed out from now on refuse all connects.
        pub fn set_fail_connect(&self, fail: bool) {
            self.fail_connect.store(fail, Ordering::SeqCst);
        }

        /// How many `probe-rs serve` **processes** were spawned.
        ///
        /// The assertion the `errno 16` regression hangs on: reuse means this
        /// stays at 1 however many channels open. Per-channel connections are
        /// counted by [`MockSession::connect_count`].
        #[must_use]
        pub fn open_count(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }

        /// The sessions handed out so far, oldest first.
        #[must_use]
        pub fn sessions(&self) -> Vec<Arc<MockSession>> {
            self.sessions.lock().unwrap().clone()
        }

        /// Total connections across every session handed out.
        #[must_use]
        pub fn connect_count(&self) -> usize {
            self.sessions()
                .iter()
                .map(|s| s.connect_count())
                .sum::<usize>()
        }
    }

    /// A handle sharing one [`MockSession`] between the agent (which owns a
    /// `Box<dyn Session>`) and the test (which keeps the `Arc`).
    struct SharedSession(Arc<MockSession>);

    #[async_trait]
    impl Session for SharedSession {
        fn board(&self) -> &str {
            self.0.board()
        }
        async fn connect(&self) -> Result<Box<dyn SpliceIo>, String> {
            self.0.connect().await
        }
        async fn kill(&self) -> Result<(), String> {
            self.0.kill().await
        }
        async fn wait(&self) -> SessionExit {
            self.0.wait().await
        }
    }

    #[async_trait]
    impl ProbeRsBackend for MockBackend {
        async fn open(
            &self,
            board: &BoardSpec,
            _serve_token: &str,
        ) -> Result<Box<dyn Session>, String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("mock backend forced failure".to_owned());
            }
            if let Some(log) = &self.log {
                log.lock().unwrap().push(format!("spawn:{}", board.id));
            }
            let session = Arc::new(match &self.log {
                Some(log) => MockSession::with_log(board.id.clone(), Arc::clone(log)),
                None => MockSession::new(board.id.clone()),
            });
            if self.fail_connect.load(Ordering::SeqCst) {
                session.fail_next_connects(usize::MAX);
            }
            self.sessions.lock().unwrap().push(Arc::clone(&session));
            Ok(Box::new(SharedSession(session)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BoardsConfig;
    // One definition, three users: see `discovery::StubLister`.
    use crate::discovery::StubLister;
    use fleet_proto::DiscoveredProbe;

    fn discovered(serial: &str, vid: u16, pid: u16) -> DiscoveredProbe {
        DiscoveredProbe {
            serial: serial.to_owned(),
            vid,
            pid,
            product: Some("J-Link".to_owned()),
            inaccessible: false,
        }
    }

    fn board() -> BoardSpec {
        let mut board = BoardsConfig::from_str(
            r#"
[[board]]
id = "nrf52840-dk-3"
serial = "001050257890"
chip = "nRF52840_xxAA"
"#,
        )
        .unwrap()
        .boards
        .remove(0);
        // vid/pid aren't declared in boards.toml; they are stamped at runtime
        // from USB discovery (see `enrich_boards_with_discovery`). The real
        // J-Link OB on the nRF52840-DK reports vid 0x1366 / pid 0x1015.
        board.vid = 0x1366;
        board.pid = 0x1015;
        board
    }

    /// A board exactly as parsed from `boards.toml`: vid/pid default to 0 until
    /// runtime discovery stamps them. Used to prove the spawn path enriches
    /// them from live enumeration (not the pre-stamped `board()` fixture).
    fn undiscovered_board() -> BoardSpec {
        BoardsConfig::from_str(
            r#"
[[board]]
id = "nrf52840-dk-3"
serial = "001050257890"
chip = "nRF52840_xxAA"
"#,
        )
        .unwrap()
        .boards
        .remove(0)
    }

    #[test]
    fn serve_spec_locks_to_probe_serial() {
        let spec = ServeSpec::for_board(&board()).unwrap();
        assert_eq!(spec.serial, "001050257890");
        assert_eq!(spec.address, "127.0.0.1");
        assert!(spec.port != 0);
        assert_eq!(spec.socket_addr(), format!("127.0.0.1:{}", spec.port));
    }

    #[test]
    fn rendered_config_is_server_table_with_access() {
        let spec = ServeSpec::for_board(&board()).unwrap();
        let cfg = spec.render_server_config("deadbeef");
        assert!(cfg.contains("[server]"));
        assert!(cfg.contains("address = \"127.0.0.1\""));
        assert!(cfg.contains(&format!("port = {}", spec.port)));
        assert!(cfg.contains("[[server.users]]"));
        assert!(cfg.contains("name = \"fleet\""));
        assert!(cfg.contains("token = \"deadbeef\""));
        // Canonical `vid:pid:serial` selector — the only form probe-rs 0.32's
        // allow-list matcher accepts. A bare serial silently filters out every
        // probe.
        assert!(cfg.contains("access = { allow = [\"1366:1015:001050257890\"] }"));
        // The bare-serial form (which never matches) must be gone.
        assert!(!cfg.contains("allow = [\"001050257890\"]"));
        // Keys we must never emit. `probe_access` is a stale, never-valid name
        // (the field is `access`). `socket://` (Unix-socket serve) and
        // `cycle_power` are *real* 0.32 `ServerConfig` features we deliberately
        // do not use. `socket://` was evaluated and **rejected** (issue #297;
        // rationale recorded in architecture §4.2, "Rejected: `socket://`
        // Unix-socket serve"): 0.32's `handle_unix_rpc` hardcodes
        // `ProbeAccess::All` and is never handed the config at all, so the
        // per-board allow-fence asserted just above cannot exist on that path.
        // This assertion pins that decision in code.
        assert!(!cfg.contains("socket://"));
        assert!(!cfg.contains("probe_access"));
        assert!(!cfg.contains("cycle_power"));
    }

    #[tokio::test]
    async fn serve_spec_enriches_vid_pid_from_discovery() {
        // A board with default 0/0 vid/pid (as parsed from boards.toml) must end
        // up rendering the *discovered* canonical selector, NOT `0000:0000:`.
        let board = undiscovered_board();
        assert_eq!((board.vid, board.pid), (0, 0));
        let dir = std::env::temp_dir().join(format!("frs-enrich-test-{}", std::process::id()));
        let be = ProcessBackend::new(dir).with_lister(Arc::new(StubLister(vec![discovered(
            "001050257890",
            0x1366,
            0x1015,
        )])));
        let spec = be.serve_spec(&board).await.unwrap();
        assert_eq!((spec.vid, spec.pid), (0x1366, 0x1015));
        let cfg = spec.render_server_config("deadbeef");
        assert!(
            cfg.contains("access = { allow = [\"1366:1015:001050257890\"] }"),
            "unexpected config: {cfg}"
        );
        // The unmatchable defaulted form must never be rendered.
        assert!(!cfg.contains("0000:0000:"));
    }

    #[tokio::test]
    async fn serve_spec_errors_when_probe_absent_rather_than_rendering_zeros() {
        // If the board's serial isn't among discovered probes, we must fail
        // loudly instead of emitting an unmatchable `0000:0000:<serial>` entry
        // (which silently no-ops every remote attach — the bug being fixed).
        let dir = std::env::temp_dir().join(format!("frs-absent-test-{}", std::process::id()));
        let be = ProcessBackend::new(dir).with_lister(Arc::new(StubLister(vec![discovered(
            "SOME-OTHER-SERIAL",
            0x1366,
            0x1015,
        )])));
        let Err(err) = be.serve_spec(&undiscovered_board()).await else {
            panic!("expected an error when the board's probe is absent");
        };
        assert!(err.contains("not found"), "unexpected error: {err}");
        assert!(err.contains("001050257890"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn serve_spec_rejects_inaccessible_probe() {
        // probe-rs 0.32 marks probes it cannot open `(inaccessible)`. Spawning
        // `serve` against one would start a server that can never attach, so we
        // fail up front and name the permissions cause.
        let dir = std::env::temp_dir().join(format!("frs-inacc-test-{}", std::process::id()));
        let probe = DiscoveredProbe {
            inaccessible: true,
            ..discovered("001050257890", 0x1366, 0x1015)
        };
        let be = ProcessBackend::new(dir).with_lister(Arc::new(StubLister(vec![probe])));
        let Err(err) = be.serve_spec(&undiscovered_board()).await else {
            panic!("expected an error when the board's probe is inaccessible");
        };
        assert!(err.contains("inaccessible"), "unexpected error: {err}");
        assert!(err.contains("001050257890"), "unexpected error: {err}");
        assert!(err.contains("permissions"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn process_backend_open_fails_without_probe_rs() {
        // With a bogus program name the serve spawn fails fast; the backend
        // surfaces a real error instead of the old not-yet-wired stub. A stub
        // lister provides the probe so we get past vid/pid resolution and reach
        // the spawn.
        let dir = std::env::temp_dir().join(format!("frs-serve-test-{}", std::process::id()));
        let be = ProcessBackend::new(dir.clone())
            .with_program("definitely-not-a-real-probe-rs-binary".to_owned())
            .with_lister(Arc::new(StubLister(vec![discovered(
                "001050257890",
                0x1366,
                0x1015,
            )])));
        let result = be.open(&undiscovered_board(), "deadbeef").await;
        std::fs::remove_dir_all(&dir).ok();
        let Err(err) = result else {
            panic!("expected spawn error")
        };
        assert!(err.contains("failed to spawn"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn mock_session_kill_then_wait_reports_killed() {
        let s = mock::MockSession::new("b1".to_owned());
        assert!(!s.was_killed());
        s.kill().await.unwrap();
        assert!(s.was_killed());
        assert_eq!(s.wait().await, SessionExit::Killed);
    }

    /// The cheap, hardware-free half of the reuse claim: one listener standing
    /// in for `probe-rs serve` accepts **two** sequential connections, so a
    /// second channel does not need a second process.
    ///
    /// (The other half — that a real `serve` hands the probe back when the
    /// first connection closes — is `ProbeBroker`'s job upstream and cannot be
    /// asserted without hardware.)
    #[tokio::test]
    async fn connect_serve_tcp_dials_the_same_server_twice() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = tokio::spawn(async move {
            let first = listener.accept().await.unwrap().0;
            // Close the first connection, exactly as a finished invocation does.
            drop(first);
            let second = listener.accept().await.unwrap().0;
            drop(second);
        });

        let a = connect_serve_tcp(&addr).await.unwrap();
        drop(a);
        let b = connect_serve_tcp(&addr)
            .await
            .expect("a second connection to a live server must succeed");
        drop(b);
        accepted.await.unwrap();
    }

    /// `connect` hands out one stream per channel, each with its own peer half.
    #[tokio::test]
    async fn mock_session_hands_out_one_stream_per_channel() {
        let s = mock::MockSession::new("b1".to_owned());
        let _first = s.connect().await.unwrap();
        let _second = s.connect().await.unwrap();
        assert_eq!(s.connect_count(), 2);
        assert!(s.take_peer().await.is_some());
        assert!(s.take_peer().await.is_some());
        assert!(s.take_peer().await.is_none());
    }
}
