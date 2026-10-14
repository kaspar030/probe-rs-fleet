//! [`WireTx`] / [`WireRx`] over `tokio-tungstenite` (feature `tungstenite`).
//!
//! Used by every dial-out role — agent, sidecar, ctl — and by the coordinator's
//! own integration tests, which drive a real client against a real router.
//!
//! Ping frames received from the peer are answered automatically by tungstenite;
//! this adapter surfaces **pongs** so the caller can decide a peer is dead, which
//! is the half that has to be explicit.

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{WireError, WireEvent, WireRx, WireTx};

/// The send half of a tungstenite `WebSocket`.
pub struct TungsteniteTx<S> {
    sink: futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
}

/// The receive half of a tungstenite `WebSocket`.
pub struct TungsteniteRx<S> {
    stream: futures_util::stream::SplitStream<WebSocketStream<S>>,
}

/// Split a `WebSocket` stream into the wire halves.
pub fn split<S>(ws: WebSocketStream<S>) -> (TungsteniteTx<S>, TungsteniteRx<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (sink, stream) = ws.split();
    (TungsteniteTx { sink }, TungsteniteRx { stream })
}

/// Map a tungstenite error onto a [`WireError`], preserving the benign-close
/// distinction the coordinator and ctl both rely on.
fn map_err(e: tokio_tungstenite::tungstenite::Error) -> WireError {
    use tokio_tungstenite::tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed => WireError::Closed,
        E::Io(io) => WireError::Io(io),
        other => WireError::Protocol(other.to_string()),
    }
}

#[async_trait::async_trait]
impl<S> WireTx for TungsteniteTx<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), WireError> {
        self.sink
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(map_err)
    }

    async fn send_ping(&mut self) -> Result<(), WireError> {
        self.sink
            .send(Message::Ping(Vec::new().into()))
            .await
            .map_err(map_err)
    }

    async fn close(&mut self) -> Result<(), WireError> {
        match self.sink.close().await.map_err(map_err) {
            // Closing an already-closed connection is the goal state, not a
            // failure.
            Ok(()) | Err(WireError::Closed) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[async_trait::async_trait]
impl<S> WireRx for TungsteniteRx<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn recv(&mut self) -> Result<WireEvent, WireError> {
        loop {
            let Some(msg) = self.stream.next().await else {
                return Ok(WireEvent::Closed);
            };
            match msg.map_err(map_err)? {
                Message::Binary(bytes) => return Ok(WireEvent::Binary(bytes.into())),
                Message::Pong(_) => return Ok(WireEvent::Pong),
                Message::Close(_) => return Ok(WireEvent::Closed),
                // tungstenite answers pings itself; nothing for us to do.
                Message::Ping(_) | Message::Frame(_) => {}
                Message::Text(_) => {
                    // This protocol is binary-only. A text message means the
                    // peer is speaking something else entirely, so refusing it
                    // loudly beats trying to interpret it.
                    return Err(WireError::Protocol(
                        "unexpected text message on a binary-only connection".to_owned(),
                    ));
                }
            }
        }
    }
}
