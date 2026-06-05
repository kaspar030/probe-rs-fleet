//! gdb-tunnel client side: a local TCP listener on the workstation that the
//! user's gdb client connects to, byte-spliced to the agent's board-local
//! `probe-rs gdb` stub through the relay (architecture §4.2 gap note, §10 Q3).
//!
//! `probe-rs gdb` is not remote-capable in probe-rs 0.31 (it runs a local TCP
//! gdb stub, not over postcard-rpc). So the fleet path does **not** exec the
//! genuine `probe-rs gdb` here. Instead:
//!
//! 1. lease/reuse the board (as for any subcommand);
//! 2. ask the coordinator to open a **gdb-kind** relay channel (the agent then
//!    spawns `probe-rs gdb` locally against the board's probe);
//! 3. open a **local** TCP listener (default [`DEFAULT_GDB_ADDR`], honoring
//!    `--gdb-connection-string`) the user points their gdb client at
//!    (`target remote :1337`);
//! 4. on `accept()`, byte-splice the accepted stream ↔ the relay gdb channel
//!    verbatim (the symmetric pump to [`fleet_agent`-side `gdb::splice`]) — pure
//!    bytes, **no** gdbremote parsing.
//!
//! Single-client is fine for v1 (gdb is one client). The pump sets
//! `TCP_NODELAY` and flushes each chunk so step-debugging is not Nagle-batched.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use fleet_proto::{ChannelId, DataFrame};

/// Default local listen address for the user's gdb client, matching probe-rs's
/// own default gdb stub address.
pub const DEFAULT_GDB_ADDR: &str = "127.0.0.1:1337";

/// Read buffer for the splice (kept small; gdb packets are tiny and forwarded
/// immediately for low latency).
const SPLICE_BUF: usize = 16 * 1024;

/// Errors from the gdb-tunnel client side.
#[derive(Debug, thiserror::Error)]
pub enum GdbError {
    /// The local listen address could not be parsed.
    #[error("invalid gdb listen address {addr:?}: {source}")]
    BadAddr {
        /// The offending address string.
        addr: String,
        /// The parse error.
        #[source]
        source: std::net::AddrParseError,
    },
    /// Binding or accepting on the local listener failed.
    #[error("gdb listener error: {0}")]
    Listen(String),
    /// The byte splice failed mid-session.
    #[error("gdb tunnel error: {0}")]
    Tunnel(String),
}

/// Resolve the local listen address for the user's gdb client from a parsed
/// `--gdb-connection-string` (or the default).
///
/// # Errors
///
/// Returns [`GdbError::BadAddr`] if the supplied string is not a valid
/// `host:port` socket address.
pub fn resolve_listen_addr(connection_string: Option<&str>) -> Result<SocketAddr, GdbError> {
    let raw = connection_string.unwrap_or(DEFAULT_GDB_ADDR);
    raw.parse().map_err(|source| GdbError::BadAddr {
        addr: raw.to_owned(),
        source,
    })
}

/// Bind a local TCP listener for the user's gdb client.
///
/// # Errors
///
/// Returns [`GdbError::Listen`] if the address cannot be bound.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, GdbError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| GdbError::Listen(format!("failed to bind {addr}: {e}")))
}

/// Accept one gdb client connection from `listener`.
///
/// gdb is single-client; v1 serves one connection per call (the caller may loop
/// for sequential reconnects within the lease).
///
/// # Errors
///
/// Returns [`GdbError::Listen`] if `accept` fails.
pub async fn accept(listener: &TcpListener) -> Result<TcpStream, GdbError> {
    let (stream, _peer) = listener
        .accept()
        .await
        .map_err(|e| GdbError::Listen(format!("accept failed: {e}")))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Bidirectionally splice the accepted gdb-client `TcpStream` with the relay
/// gdb channel, copying bytes verbatim in both directions until either side
/// closes.
///
/// * Bytes read from `stream` (← the user's gdb client) are wrapped in
///   `DataFrame { channel, bytes }` and sent to `to_relay` (→ coordinator →
///   agent → agent-side `probe-rs gdb` stub).
/// * `DataFrame`s arriving on `from_relay` (← the agent's stub) are written to
///   `stream` (→ the user's gdb client).
///
/// This is the exact mirror of the agent-side pump. Each chunk is flushed
/// immediately for low latency.
///
/// # Errors
///
/// Returns [`GdbError::Tunnel`] on a TCP read/write failure. A clean EOF on
/// either side is *not* an error.
pub async fn splice(
    channel: ChannelId,
    mut stream: TcpStream,
    to_relay: mpsc::Sender<DataFrame>,
    mut from_relay: mpsc::Receiver<DataFrame>,
) -> Result<(), GdbError> {
    let mut buf = vec![0u8; SPLICE_BUF];
    loop {
        tokio::select! {
            // gdb client -> relay
            read = stream.read(&mut buf) => {
                let n = read.map_err(|e| GdbError::Tunnel(format!("client tcp read failed: {e}")))?;
                if n == 0 {
                    // gdb client disconnected: end the session.
                    return Ok(());
                }
                let frame = DataFrame { channel, bytes: buf[..n].to_vec() };
                if to_relay.send(frame).await.is_err() {
                    return Ok(());
                }
            }
            // relay -> gdb client
            inbound = from_relay.recv() => {
                let Some(frame) = inbound else {
                    return Ok(());
                };
                stream
                    .write_all(&frame.bytes)
                    .await
                    .map_err(|e| GdbError::Tunnel(format!("client tcp write failed: {e}")))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| GdbError::Tunnel(format!("client tcp flush failed: {e}")))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_addr_is_loopback_1337() {
        let addr = resolve_listen_addr(None).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 1337);
    }

    #[test]
    fn honors_connection_string() {
        let addr = resolve_listen_addr(Some("127.0.0.1:3333")).unwrap();
        assert_eq!(addr.port(), 3333);
    }

    #[test]
    fn rejects_bad_connection_string() {
        let err = resolve_listen_addr(Some("not-an-addr")).unwrap_err();
        assert!(matches!(err, GdbError::BadAddr { .. }));
    }

    /// The acceptance test for the sidecar end: a gdb client connecting to the
    /// local listener round-trips bytes both directions through the splice ↔
    /// relay channel, verbatim and in order.
    #[tokio::test]
    async fn splice_round_trips_both_directions() {
        let listener = bind(resolve_listen_addr(Some("127.0.0.1:0")).unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // The user's gdb client dials the local listener.
        let client = TcpStream::connect(addr);
        let accepted = accept(&listener);
        let (client, accepted) = tokio::join!(client, accepted);
        let mut client = client.unwrap();
        let accepted = accepted.unwrap();

        let channel = ChannelId(11);
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<DataFrame>(16);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<DataFrame>(16);
        let splice_task =
            tokio::spawn(splice(channel, accepted, to_relay_tx, from_relay_rx));

        // client -> relay
        client.write_all(b"$g#67").await.unwrap();
        client.flush().await.unwrap();
        let frame = to_relay_rx.recv().await.unwrap();
        assert_eq!(frame.channel, channel);
        assert_eq!(frame.bytes, b"$g#67");

        // relay -> client
        from_relay_tx
            .send(DataFrame {
                channel,
                bytes: b"+$T05#bb".to_vec(),
            })
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"+$T05#bb");

        // Client disconnect ends the splice cleanly.
        drop(client);
        let result = splice_task.await.unwrap();
        assert!(result.is_ok());
    }
}
