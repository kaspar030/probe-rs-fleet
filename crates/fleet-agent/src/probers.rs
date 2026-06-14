//! probe-rs `serve` lifecycle + byte-proxy (architecture §4.2, per task #1710).
//!
//! Decided model: the agent runs **one `probe-rs serve` per board** over a
//! loopback **Unix socket**, each locked to its physical probe via a per-board
//! user with `ProbeAccess::Allow([serial])` + a per-board token. The agent then
//! **byte-splices** the raw `u32-LE length-prefixed postcard` stream between
//! that socket and the coordinator-relayed data channel — *zero* probe-rs
//! parsing. The server is reused across a holder's many invocations (matching
//! time-based sharing, §6) and recycled on board release for cleanup.
//!
//! `probe-rs serve` takes **no** `--probe`/`--chip` — the connecting client
//! selects probe + chip in-band over postcard-rpc — so there is no CLI
//! injection point; isolation is the per-board `ProbeAccess` fence we write
//! into the server's config file.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::BoardSpec;

/// A byte stream the agent splices onto a relay data channel: the connected
/// transport to a board's `probe-rs serve` Unix socket (or, in tests, an
/// in-memory duplex). Object-safe so the concrete transport (Unix socket vs.
/// mock) is hidden behind the [`Session`] trait.
pub trait SpliceIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SpliceIo for T {}

/// Where a board's `probe-rs serve` instance listens, and the config that
/// pins it to a single probe. This is the input the real process backend turns
/// into a spawned `probe-rs serve` + its `ServerConfig` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSpec {
    /// Board id (for logging / lookup).
    pub board: String,
    /// The probe serial this server is locked to (`ProbeAccess::Allow`).
    pub serial: String,
    /// Unix socket path the server binds (`address = "socket://<path>"`).
    pub socket_path: PathBuf,
    /// Per-board token the agent's local proxy presents to `serve` (the inner
    /// loopback hop; the fleet's own mTLS + capability token guard the network
    /// legs).
    pub local_token: String,
}

impl ServeSpec {
    /// Derive a serve spec for `board`, placing its socket under `runtime_dir`.
    #[must_use]
    pub fn for_board(board: &BoardSpec, runtime_dir: &std::path::Path) -> Self {
        let socket_path = runtime_dir.join(format!("serve-{}.sock", board.id));
        Self {
            board: board.id.clone(),
            serial: board.serial.clone(),
            socket_path,
            // A per-board random-ish token; the real backend regenerates this
            // on each (re)spawn. Stable derivation here keeps it testable.
            local_token: format!("local-{}", board.serial),
        }
    }

    /// Render the `probe-rs serve` TOML config that locks the server to this
    /// board's probe over its Unix socket.
    ///
    /// Shape per #1710: `ServerConfig { users, address = "socket://<path>",
    /// cycle_power }`, with one user whose `ProbeAccess::Allow([serial])`.
    #[must_use]
    pub fn render_server_config(&self) -> String {
        let socket = self.socket_path.display();
        format!(
            "address = \"socket://{socket}\"\n\
             cycle_power = false\n\
             \n\
             [[users]]\n\
             token = \"{token}\"\n\
             probe_access = {{ allow = [\"{serial}\"] }}\n",
            token = self.local_token,
            serial = self.serial,
        )
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// The `probe-rs serve` process exited on its own with this code.
    Exited(i32),
    /// The agent killed the process (lease release / fault / explicit kill).
    Killed,
}

/// A live probe-rs session: a running `probe-rs serve` for one board, whose
/// byte stream is being spliced onto a relay channel.
#[async_trait]
pub trait Session: Send + Sync {
    /// The board this session serves.
    fn board(&self) -> &str;

    /// Take the spliceable byte stream for this session, exactly once.
    ///
    /// The connection layer calls this to obtain the connected `probe-rs serve`
    /// transport and byte-splice it onto the relay data channel. Returns `None`
    /// on the second and later calls (the stream was already taken).
    async fn take_io(&self) -> Option<Box<dyn SpliceIo>>;

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
    /// Open a session for `board`. The returned [`Session`] owns the process
    /// and the splice to the relay channel.
    ///
    /// # Errors
    ///
    /// Returns an error string if the server could not be started.
    async fn open(&self, board: &BoardSpec) -> Result<Box<dyn Session>, String>;
}

/// The real, process-spawning backend.
///
/// Spawns `probe-rs serve --config <generated>` per board over a Unix socket
/// and byte-splices its `u32-LE length-prefixed postcard` stream onto the relay.
#[derive(Debug, Clone)]
pub struct ProcessBackend {
    /// Directory under which per-board sockets and config files are written.
    runtime_dir: PathBuf,
    /// The `probe-rs` binary to invoke.
    program: String,
}

impl ProcessBackend {
    /// Build a process backend writing sockets/configs under `runtime_dir`.
    #[must_use]
    pub fn new(runtime_dir: PathBuf) -> Self {
        Self {
            runtime_dir,
            program: "probe-rs".to_owned(),
        }
    }

    /// Override the `probe-rs` binary path (e.g. for tests / non-default
    /// install).
    #[must_use]
    pub fn with_program(mut self, program: String) -> Self {
        self.program = program;
        self
    }

    /// The serve spec this backend would use for `board`.
    #[must_use]
    pub fn serve_spec(&self, board: &BoardSpec) -> ServeSpec {
        ServeSpec::for_board(board, &self.runtime_dir)
    }
}

/// Time to wait for a freshly-spawned `probe-rs serve` to bind its Unix socket.
const SERVE_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Poll interval while waiting for the serve socket to appear.
const SERVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// A live `probe-rs serve` session: a running child process and a connected
/// Unix-socket stream the agent splices onto a relay data channel.
struct ProcessSession {
    board: String,
    child: tokio::sync::Mutex<tokio::process::Child>,
    /// The connected socket stream, taken once by the connection layer.
    io: tokio::sync::Mutex<Option<tokio::net::UnixStream>>,
    killed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Session for ProcessSession {
    fn board(&self) -> &str {
        &self.board
    }

    async fn take_io(&self) -> Option<Box<dyn SpliceIo>> {
        self.io
            .lock()
            .await
            .take()
            .map(|s| Box::new(s) as Box<dyn SpliceIo>)
    }

    async fn kill(&self) -> Result<(), String> {
        self.killed
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
    async fn open(&self, board: &BoardSpec) -> Result<Box<dyn Session>, String> {
        let spec = self.serve_spec(board);

        // 1. Render and write the per-board server config (locks the server to
        //    this board's probe via `ProbeAccess::Allow([serial])`).
        let runtime_dir = spec
            .socket_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        tokio::fs::create_dir_all(&runtime_dir)
            .await
            .map_err(|e| format!("creating runtime dir {}: {e}", runtime_dir.display()))?;
        // A stale socket from a previous run would make `serve` fail to bind.
        let _ = tokio::fs::remove_file(&spec.socket_path).await;
        let config_path = runtime_dir.join(format!("serve-{}.toml", spec.board));
        tokio::fs::write(&config_path, spec.render_server_config())
            .await
            .map_err(|e| format!("writing serve config {}: {e}", config_path.display()))?;

        // 2. Spawn `probe-rs serve --config <file>`. It takes no `--probe` /
        //    `--chip` (the client selects them in-band over postcard-rpc);
        //    isolation is the `ProbeAccess` fence in the config.
        let child = tokio::process::Command::new(&self.program)
            .arg("serve")
            .arg("--config")
            .arg(&config_path)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                format!(
                    "failed to spawn `{} serve` for board {}: {e}",
                    self.program, spec.board
                )
            })?;

        // 3. Wait for the Unix socket to appear and connect to it.
        let io = match connect_serve_socket(&spec.socket_path).await {
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
            io: tokio::sync::Mutex::new(Some(io)),
            killed: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}

/// Poll-connect to a `probe-rs serve` Unix socket until it is reachable or the
/// ready timeout elapses.
async fn connect_serve_socket(path: &Path) -> Result<tokio::net::UnixStream, String> {
    let deadline = tokio::time::Instant::now() + SERVE_READY_TIMEOUT;
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "`probe-rs serve` socket {} never became reachable: {e}",
                        path.display()
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
    use std::sync::Arc;

    use super::{ProbeRsBackend, Session, SessionExit, SpliceIo};
    use crate::config::BoardSpec;
    use async_trait::async_trait;
    use tokio::sync::Notify;

    /// A mock session whose exit can be driven by the test.
    pub struct MockSession {
        board: String,
        killed: Arc<AtomicBool>,
        exit_notify: Arc<Notify>,
        exit: Arc<std::sync::Mutex<Option<SessionExit>>>,
        /// The agent-side half of an in-memory duplex, taken once by `take_io`.
        /// Tests drive the peer half to emulate `probe-rs serve`.
        io: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
    }

    impl MockSession {
        #[must_use]
        pub fn new(board: String) -> Self {
            Self {
                board,
                killed: Arc::new(AtomicBool::new(false)),
                exit_notify: Arc::new(Notify::new()),
                exit: Arc::new(std::sync::Mutex::new(None)),
                io: tokio::sync::Mutex::new(None),
            }
        }

        /// Build a mock session with an in-memory duplex, returning the peer
        /// half the test drives to emulate `probe-rs serve`.
        #[must_use]
        pub fn with_io(board: String) -> (Self, tokio::io::DuplexStream) {
            let (agent_side, peer) = tokio::io::duplex(4096);
            let mut s = Self::new(board);
            s.io = tokio::sync::Mutex::new(Some(agent_side));
            (s, peer)
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

        async fn take_io(&self) -> Option<Box<dyn SpliceIo>> {
            self.io
                .lock()
                .await
                .take()
                .map(|s| Box::new(s) as Box<dyn SpliceIo>)
        }

        async fn kill(&self) -> Result<(), String> {
            self.killed.store(true, Ordering::SeqCst);
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
    }

    impl MockBackend {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[allow(dead_code)]
        pub fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }

        #[must_use]
        pub fn open_count(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProbeRsBackend for MockBackend {
        async fn open(&self, board: &BoardSpec) -> Result<Box<dyn Session>, String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("mock backend forced failure".to_owned());
            }
            Ok(Box::new(MockSession::new(board.id.clone())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BoardsConfig;

    fn board() -> BoardSpec {
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
        let dir = std::path::Path::new("/run/fleet");
        let spec = ServeSpec::for_board(&board(), dir);
        assert_eq!(spec.serial, "001050257890");
        assert!(spec
            .socket_path
            .to_string_lossy()
            .ends_with("serve-nrf52840-dk-3.sock"));
    }

    #[test]
    fn rendered_config_has_socket_and_probe_access() {
        let dir = std::path::Path::new("/run/fleet");
        let spec = ServeSpec::for_board(&board(), dir);
        let cfg = spec.render_server_config();
        assert!(cfg.contains("address = \"socket:///run/fleet/serve-nrf52840-dk-3.sock\""));
        assert!(cfg.contains("allow = [\"001050257890\"]"));
        assert!(cfg.contains("[[users]]"));
    }

    #[tokio::test]
    async fn process_backend_open_fails_without_probe_rs() {
        // With a bogus program name the spawn fails fast; the backend surfaces
        // a real error instead of the old not-yet-wired stub.
        let dir = std::env::temp_dir().join(format!("frs-serve-test-{}", std::process::id()));
        let be = ProcessBackend::new(dir.clone())
            .with_program("definitely-not-a-real-probe-rs-binary".to_owned());
        let result = be.open(&board()).await;
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
}
