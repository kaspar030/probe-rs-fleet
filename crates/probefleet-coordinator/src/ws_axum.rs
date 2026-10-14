//! [`WireTx`] / [`WireRx`] over `axum`'s `WebSocket`.
//!
//! The server-side counterpart of `fleet_wire::tungstenite`. It lives **here**,
//! not in `fleet-wire`, so that `fleet-agent` and `fleet-sidecar` — libraries
//! that move probe bytes and dial outward — never link an HTTP server
//! framework. That is a layering rule about dependency direction, not a binary
//! size requirement: `fleet-bin` links the coordinator and therefore ships axum
//! onto the Pi regardless.

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};

use fleet_wire::{WireError, WireEvent, WireRx, WireTx};

/// The send half of an axum `WebSocket`.
pub struct AxumTx {
    sink: SplitSink<WebSocket, Message>,
}

/// The receive half of an axum `WebSocket`.
pub struct AxumRx {
    stream: SplitStream<WebSocket>,
}

/// Split an axum `WebSocket` into the wire halves.
#[must_use]
pub fn split(ws: WebSocket) -> (AxumTx, AxumRx) {
    let (sink, stream) = ws.split();
    (AxumTx { sink }, AxumRx { stream })
}

/// Map an axum `WebSocket` error onto a [`WireError`].
///
/// axum funnels everything through `axum::Error`, so the benign-close cases have
/// to be recovered from the source chain rather than matched on a variant.
fn map_err(e: &axum::Error) -> WireError {
    let text = e.to_string();
    if text.contains("Connection closed normally")
        || text.contains("connection closed")
        || text.contains("already closed")
    {
        return WireError::Closed;
    }
    WireError::Protocol(text)
}

#[async_trait::async_trait]
impl WireTx for AxumTx {
    async fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), WireError> {
        self.sink
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| map_err(&e))
    }

    async fn send_ping(&mut self) -> Result<(), WireError> {
        self.sink
            .send(Message::Ping(Vec::new().into()))
            .await
            .map_err(|e| map_err(&e))
    }

    async fn close(&mut self) -> Result<(), WireError> {
        match self.sink.close().await.map_err(|e| map_err(&e)) {
            Ok(()) | Err(WireError::Closed) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[async_trait::async_trait]
impl WireRx for AxumRx {
    async fn recv(&mut self) -> Result<WireEvent, WireError> {
        loop {
            let Some(msg) = self.stream.next().await else {
                return Ok(WireEvent::Closed);
            };
            match msg.map_err(|e| map_err(&e))? {
                Message::Binary(bytes) => return Ok(WireEvent::Binary(bytes.into())),
                Message::Pong(_) => return Ok(WireEvent::Pong),
                Message::Close(_) => return Ok(WireEvent::Closed),
                // axum/tungstenite answers pings itself.
                Message::Ping(_) => {}
                Message::Text(_) => {
                    // The control plane is binary-only; a text message means the
                    // peer is speaking a different protocol entirely.
                    return Err(WireError::Protocol(
                        "unexpected text message on a binary-only connection".to_owned(),
                    ));
                }
            }
        }
    }
}
