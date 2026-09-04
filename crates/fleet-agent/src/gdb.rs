//! gdb-channel support: tunnel a board-local `probe-rs gdb` TCP stub as a
//! second opaque relay channel (architecture §4.2 gap note, §10 Q3).
//!
//! `probe-rs gdb` is **not** remote-capable in probe-rs 0.32 (re-verified at
//! the v0.32.0 tag): it ignores any
//! RPC client and binds a local gdbremote TCP stub (default `127.0.0.1:1337`,
//! `--gdb-connection-string` overridable), entirely outside postcard-rpc. So it
//! cannot ride the data plane. Instead, on a [`ChannelKind::Gdb`] open the agent
//! runs `probe-rs gdb` **locally** against the leased board's probe, binds its
//! stub to an **ephemeral loopback port**, connects a [`TcpStream`] to it, and
//! byte-splices that stream onto the relay channel.
//!
//! [`ChannelKind::Gdb`]: fleet_proto::ChannelKind
//!
//! ## Two halves
//!
//! * [`GdbStub`] — the spawn-and-connect seam. The real [`ProcessGdbStub`]
//!   spawns `probe-rs gdb --chip <chip> --probe <serial> --gdb-connection-string
//!   127.0.0.1:<ephemeral>` and dials its listener; tests inject a mock that
//!   hands back a loopback `TcpStream` pair, so the splice is exercised without
//!   any probe-rs binary or hardware. Unlike `serve`, the `gdb` subcommand
//!   *does* accept `--probe` / `--chip`, so per-board isolation is by argument.
//! * [`splice`] — the bidirectional byte pump that copies the connected TCP
//!   stream ↔ the relay channel verbatim. The same shape runs on the sidecar
//!   end ([`crate`] mirror in `fleet-sidecar`); it is pure byte relay with
//!   **zero** gdbremote parsing.
//!
//! Latency: the pump flushes each chunk immediately and sets `TCP_NODELAY` on
//! the loopback hop so step-debugging is not Nagle-batched. The two relay hops
//! (sidecar→coordinator and coordinator→agent, both `WebSocket`s over HTTPS) add ~2×RTT per gdb round-trip; gdb is request/response and tolerant of
//! LAN-scale RTT, so this is acceptable for interactive use (revisit if
//! step-debugging feels sluggish — see `docs/architecture.md` §10 Q3).

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use fleet_proto::{ChannelId, DataFrame};

use crate::config::BoardSpec;

/// Read buffer for the splice. gdb packets are small; this bounds a single
/// `DataFrame` while keeping latency low (each read is forwarded immediately).
const SPLICE_BUF: usize = 16 * 1024;

/// How long to wait for a freshly-spawned `probe-rs gdb` stub to start
/// listening before giving up.
const STUB_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff between poll-connect attempts while waiting for the stub's listener.
const STUB_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A live, board-local `probe-rs gdb` stub: a running process plus a TCP
/// connection to its gdbremote listener.
///
/// The agent splices [`GdbConnection::stream`] onto the relay channel and
/// [`GdbConnection::shutdown`]s it (killing the process) on channel close /
/// lease release / fault.
pub struct GdbConnection {
    /// The connected TCP stream to the stub's gdbremote listener, taken once by
    /// the connection layer for splicing.
    pub stream: Option<TcpStream>,
    /// Kills the underlying `probe-rs gdb` process on shutdown.
    killer: Box<dyn GdbKill>,
}

impl GdbConnection {
    /// Wrap a connected stream and its process killer.
    #[must_use]
    pub fn new(stream: TcpStream, killer: Box<dyn GdbKill>) -> Self {
        Self {
            stream: Some(stream),
            killer,
        }
    }

    /// Take the connected gdbremote TCP stream for splicing, exactly once.
    pub fn take_stream(&mut self) -> Option<TcpStream> {
        self.stream.take()
    }

    /// Kill the underlying `probe-rs gdb` process. Idempotent / best-effort.
    pub async fn shutdown(self) {
        self.killer.kill().await;
    }
}

/// Kills a spawned `probe-rs gdb` process. Abstracted so tests can use a no-op.
#[async_trait]
pub trait GdbKill: Send + Sync {
    /// Terminate the process. Best-effort; errors are swallowed by callers.
    async fn kill(&self);
}

/// A [`GdbKill`] that does nothing (mock / tests, or a stub with no process).
pub struct NoKill;

#[async_trait]
impl GdbKill for NoKill {
    async fn kill(&self) {}
}

/// Spawns a board-local `probe-rs gdb` stub and connects to it.
///
/// Abstracted as a trait so the agent's gdb lifecycle is unit-tested with a
/// mock that returns a loopback `TcpStream`; the real [`ProcessGdbStub`] spawns
/// the genuine process.
#[async_trait]
pub trait GdbStub: Send + Sync {
    /// Spawn `probe-rs gdb` for `board` on an ephemeral loopback port, wait for
    /// its listener, and connect to it.
    ///
    /// # Errors
    ///
    /// Returns an error string if the process could not be started or its
    /// listener never became reachable.
    async fn spawn(&self, board: &BoardSpec) -> Result<GdbConnection, String>;
}

/// The real, process-spawning gdb stub backend.
#[derive(Debug, Clone)]
pub struct ProcessGdbStub {
    /// The `probe-rs` binary to invoke.
    program: String,
}

impl Default for ProcessGdbStub {
    fn default() -> Self {
        Self {
            program: "probe-rs".to_owned(),
        }
    }
}

impl ProcessGdbStub {
    /// A process gdb-stub backend invoking the default `probe-rs` binary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the `probe-rs` binary path (tests / non-default install).
    #[must_use]
    pub fn with_program(mut self, program: String) -> Self {
        self.program = program;
        self
    }

    /// The argv (after the program name) this backend would use to spawn the
    /// stub for `board` bound to `addr`. Factored out for unit testing the
    /// argument shape without spawning a process.
    #[must_use]
    pub fn gdb_args(board: &BoardSpec, addr: SocketAddr) -> Vec<String> {
        vec![
            "gdb".to_owned(),
            "--chip".to_owned(),
            board.chip.clone(),
            "--probe".to_owned(),
            board.serial.clone(),
            "--gdb-connection-string".to_owned(),
            addr.to_string(),
        ]
    }
}

/// A [`GdbKill`] that kills a `tokio::process::Child`.
struct ChildKill {
    child: tokio::sync::Mutex<tokio::process::Child>,
}

#[async_trait]
impl GdbKill for ChildKill {
    async fn kill(&self) {
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

#[async_trait]
impl GdbStub for ProcessGdbStub {
    async fn spawn(&self, board: &BoardSpec) -> Result<GdbConnection, String> {
        // Bind an ephemeral loopback port ourselves, then hand its address to
        // `probe-rs gdb` via `--gdb-connection-string`. Binding port 0 and
        // immediately dropping the listener races, so instead we reserve the
        // port, learn the address, drop the listener, and tell the stub to
        // bind it. This avoids the fixed-1337 clash when several boards run gdb
        // concurrently on one Pi.
        let addr = reserve_loopback_port().await?;
        let args = Self::gdb_args(board, addr);

        let child = tokio::process::Command::new(&self.program)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                format!(
                    "failed to spawn `{} gdb` for board {}: {e}",
                    self.program, board.id
                )
            })?;

        let killer: Box<dyn GdbKill> = Box::new(ChildKill {
            child: tokio::sync::Mutex::new(child),
        });

        match connect_with_backoff(addr).await {
            Ok(stream) => Ok(GdbConnection::new(stream, killer)),
            Err(e) => {
                killer.kill().await;
                Err(e)
            }
        }
    }
}

/// Reserve an ephemeral loopback port by binding and then releasing it,
/// returning the address the caller should ask a child to bind.
async fn reserve_loopback_port() -> Result<SocketAddr, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to reserve loopback port: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read reserved port: {e}"))?;
    drop(listener);
    Ok(addr)
}

/// Poll-connect to `addr` with a short backoff until the stub's listener is up
/// or [`STUB_READY_TIMEOUT`] elapses.
async fn connect_with_backoff(addr: SocketAddr) -> Result<TcpStream, String> {
    let deadline = tokio::time::Instant::now() + STUB_READY_TIMEOUT;
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "`probe-rs gdb` stub at {addr} never became reachable: {e}"
                    ));
                }
                tokio::time::sleep(STUB_POLL_INTERVAL).await;
            }
        }
    }
}

/// Bidirectionally splice a connected gdb `TcpStream` with the relay channel,
/// copying bytes verbatim in both directions until either side closes.
///
/// * Bytes read from `stream` are wrapped in `DataFrame { channel, bytes }` and
///   sent to `to_relay` (→ coordinator → sidecar → user's gdb client).
/// * `DataFrame`s arriving on `from_relay` (← user's gdb client) are written to
///   `stream`.
///
/// Each chunk is flushed immediately for low latency. Returns when the TCP
/// stream reaches EOF, the relay channel closes, or an I/O error occurs.
///
/// # Errors
///
/// Returns an error string on a TCP read/write failure. A clean EOF on either
/// side is *not* an error.
pub async fn splice(
    channel: ChannelId,
    mut stream: TcpStream,
    to_relay: mpsc::Sender<DataFrame>,
    mut from_relay: mpsc::Receiver<DataFrame>,
) -> Result<(), String> {
    let mut buf = vec![0u8; SPLICE_BUF];
    loop {
        tokio::select! {
            // TCP -> relay
            read = stream.read(&mut buf) => {
                let n = read.map_err(|e| format!("gdb tcp read failed: {e}"))?;
                if n == 0 {
                    // The local gdb stub closed: tear the channel down.
                    return Ok(());
                }
                let frame = DataFrame { channel, bytes: buf[..n].to_vec() };
                if to_relay.send(frame).await.is_err() {
                    // Relay closed: nothing more to forward.
                    return Ok(());
                }
            }
            // relay -> TCP
            inbound = from_relay.recv() => {
                let Some(frame) = inbound else {
                    // Relay closed.
                    return Ok(());
                };
                stream
                    .write_all(&frame.bytes)
                    .await
                    .map_err(|e| format!("gdb tcp write failed: {e}"))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| format!("gdb tcp flush failed: {e}"))?;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A mock [`GdbStub`] that returns a loopback `TcpStream` connected to an
    //! in-test "stub" half, so the splice can be exercised end-to-end without
    //! probe-rs.

    use super::{GdbConnection, GdbKill, GdbStub, NoKill};
    use crate::config::BoardSpec;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpStream;

    /// Open a connected loopback `TcpStream` pair: `(agent_side, stub_side)`.
    /// The agent splices `agent_side`; the test drives `stub_side` to emulate
    /// the `probe-rs gdb` process.
    pub async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        let client = client.unwrap();
        let (server, _) = accepted.unwrap();
        client.set_nodelay(true).unwrap();
        (client, server)
    }

    /// A mock backend that hands out a loopback stream and counts spawns.
    #[derive(Default)]
    pub struct MockGdbStub {
        spawns: AtomicUsize,
    }

    impl MockGdbStub {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn spawn_count(&self) -> usize {
            self.spawns.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl GdbStub for MockGdbStub {
        async fn spawn(&self, _board: &BoardSpec) -> Result<GdbConnection, String> {
            self.spawns.fetch_add(1, Ordering::SeqCst);
            let (agent_side, stub_side) = loopback_pair().await;
            // Leak the stub side onto a task that echoes, so a basic spawn test
            // sees a live peer. Callers wanting to drive the stub use
            // `loopback_pair` directly.
            tokio::spawn(async move {
                let _keep = stub_side;
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            });
            let killer: Box<dyn GdbKill> = Box::new(NoKill);
            Ok(GdbConnection::new(agent_side, killer))
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
    fn gdb_args_pass_chip_probe_and_connection_string() {
        let addr: SocketAddr = "127.0.0.1:51999".parse().unwrap();
        let args = ProcessGdbStub::gdb_args(&board(), addr);
        assert_eq!(args[0], "gdb");
        // chip + probe are passed explicitly (gdb, unlike serve, accepts them).
        let chip_idx = args.iter().position(|a| a == "--chip").unwrap();
        assert_eq!(args[chip_idx + 1], "nRF52840_xxAA");
        let probe_idx = args.iter().position(|a| a == "--probe").unwrap();
        assert_eq!(args[probe_idx + 1], "001050257890");
        let gcs_idx = args
            .iter()
            .position(|a| a == "--gdb-connection-string")
            .unwrap();
        assert_eq!(args[gcs_idx + 1], "127.0.0.1:51999");
    }

    #[tokio::test]
    async fn reserve_loopback_port_is_loopback() {
        let addr = reserve_loopback_port().await.unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }

    /// The core acceptance test: the bidirectional splice round-trips bytes
    /// both directions, in order, with no loss — over a real loopback TCP
    /// stream ↔ in-memory relay channel.
    #[tokio::test]
    async fn splice_round_trips_both_directions() {
        let (agent_side, mut stub_side) = mock::loopback_pair().await;
        let channel = ChannelId(7);
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<DataFrame>(16);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<DataFrame>(16);

        let splice_task =
            tokio::spawn(splice(channel, agent_side, to_relay_tx, from_relay_rx));

        // stub -> agent -> relay: the stub writes gdb bytes; they arrive on the
        // relay channel verbatim, tagged with the right channel id.
        stub_side.write_all(b"$qSupported#37").await.unwrap();
        stub_side.flush().await.unwrap();
        let frame = to_relay_rx.recv().await.unwrap();
        assert_eq!(frame.channel, channel);
        assert_eq!(frame.bytes, b"$qSupported#37");

        // relay -> agent -> stub: a frame from the relay is written to the TCP
        // stream and read by the stub.
        from_relay_tx
            .send(DataFrame {
                channel,
                bytes: b"+$OK#9a".to_vec(),
            })
            .await
            .unwrap();
        let mut buf = [0u8; 7];
        stub_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"+$OK#9a");

        // Closing the stub side ends the splice cleanly.
        drop(stub_side);
        let result = splice_task.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn splice_ends_when_relay_closes() {
        let (agent_side, _stub_side) = mock::loopback_pair().await;
        let (to_relay_tx, _to_relay_rx) = mpsc::channel::<DataFrame>(16);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<DataFrame>(16);
        let task = tokio::spawn(splice(ChannelId(1), agent_side, to_relay_tx, from_relay_rx));
        // Drop the inbound sender: the relay side is gone.
        drop(from_relay_tx);
        let result = task.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_stub_hands_out_connected_stream() {
        let stub = mock::MockGdbStub::new();
        let conn = stub.spawn(&board()).await.unwrap();
        assert_eq!(stub.spawn_count(), 1);
        // The returned stream is connected (peer addr resolves).
        assert!(conn.stream.as_ref().unwrap().peer_addr().is_ok());
        conn.shutdown().await;
    }
}
