//! The shared `WebSocket` dial helper (feature `tungstenite`).
//!
//! **The one place in the tree that builds a `WebSocket` upgrade request.** The
//! agent, the sidecar and `ctl` all dial through here, which is why the bearer
//! header, the URL normalisation and the TLS trust configuration cannot drift
//! between them — before revision 2 there were three near-identical hand-rolled
//! `connect` + `server_name` implementations, and they *had* drifted.
//!
//! # URL handling without `url`
//!
//! Architecture §3.5 needs exactly two operations: swap `http(s)` for `ws(s)`
//! and append a fixed route. That is a short function over [`http::Uri`], and it
//! avoids pulling the `url` crate, which drags `idna` and the whole `icu_*`
//! unicode stack onto a Raspberry Pi to do nothing we need.
//!
//! A bare `host:port` is accepted and defaults to `https`, because that is what
//! operators type and what the old config field contained.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::tungstenite::{split, TungsteniteRx, TungsteniteTx};
use crate::{WireError, MAX_FRAME_LEN};

/// Where and how to dial the coordinator.
#[derive(Debug, Clone)]
pub struct DialOpts {
    /// The coordinator's base URL: `https://host[:port]`, `http://…`, or a bare
    /// `host:port` (which defaults to `https`).
    pub url: String,
    /// The route to open: `/agent` for nodes, `/client` for ctl and sidecars.
    pub path: &'static str,
    /// The bearer credential presented on the upgrade.
    pub bearer: String,
    /// Optional pinned server-certificate SHA-256, for a self-hosted
    /// coordinator with no publicly trusted certificate.
    pub pin: Option<[u8; 32]>,
}

/// The connected wire halves returned by [`dial`].
pub type DialedTx = TungsteniteTx<MaybeTlsStream<TcpStream>>;
/// The receive half returned by [`dial`].
pub type DialedRx = TungsteniteRx<MaybeTlsStream<TcpStream>>;

/// Rewrite a coordinator base URL into the `ws(s)://…<path>` upgrade target.
///
/// # Errors
///
/// Returns [`WireError::Protocol`] if the URL has no host or an unsupported
/// scheme.
pub fn upgrade_url(base: &str, path: &str) -> Result<String, WireError> {
    let base = base.trim();
    if base.is_empty() {
        return Err(WireError::Protocol("coordinator URL is empty".to_owned()));
    }
    let with_scheme = if base.contains("://") {
        base.to_owned()
    } else {
        format!("https://{base}")
    };
    let uri: http::Uri = with_scheme
        .parse()
        .map_err(|e| WireError::Protocol(format!("invalid coordinator URL: {e}")))?;
    let ws_scheme = match uri.scheme_str() {
        Some("https" | "wss") => "wss",
        Some("http" | "ws") => "ws",
        Some(other) => {
            return Err(WireError::Protocol(format!(
                "unsupported coordinator URL scheme `{other}`"
            )))
        }
        None => "wss",
    };
    let authority = uri
        .authority()
        .filter(|a| !a.host().is_empty())
        .ok_or_else(|| WireError::Protocol("coordinator URL has no host".to_owned()))?;
    // A base URL may carry a path prefix when the coordinator is mounted under
    // a sub-path of a reverse proxy; keep it and append the route.
    let prefix = uri.path().trim_end_matches('/');
    Ok(format!("{ws_scheme}://{authority}{prefix}{path}"))
}

/// The `WebSocket` configuration both ends must agree on.
///
/// `max_message_size` is pinned to [`MAX_FRAME_LEN`] rather than left at
/// tungstenite's default: if the two diverge, a large-but-legal message (a 16
/// MiB flash chunk) fails only in production, and only on the end with the
/// smaller limit.
#[must_use]
pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_LEN))
        .max_frame_size(Some(MAX_FRAME_LEN))
}

/// Dial the coordinator, presenting `bearer` on the upgrade.
///
/// # Errors
///
/// Returns [`WireError::Protocol`] if the URL or the bearer header is
/// unusable, and [`WireError::Io`] / [`WireError::Protocol`] if the connection
/// or the `WebSocket` handshake fails.
pub async fn dial(opts: DialOpts) -> Result<(DialedTx, DialedRx), WireError> {
    let ws = dial_stream(opts).await?;
    Ok(split(ws))
}

/// As [`dial`], but returning the raw `WebSocket` stream.
///
/// # Errors
///
/// See [`dial`].
pub async fn dial_stream(
    opts: DialOpts,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WireError> {
    let url = upgrade_url(&opts.url, opts.path)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| WireError::Protocol(format!("building upgrade request: {e}")))?;
    let value = format!("Bearer {}", opts.bearer.trim());
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        value
            .parse()
            .map_err(|_| WireError::Protocol("credential is not a valid header value".to_owned()))?,
    );

    // One trust path, shared with the `/auth/token` HTTP client: see
    // `fleet_tls::client_trust_config`.
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(
        fleet_tls::client_trust_config(opts.pin),
    ));

    let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(websocket_config()),
        false,
        Some(connector),
    )
    .await
    .map_err(|e| match e {
        tokio_tungstenite::tungstenite::Error::Io(io) => WireError::Io(io),
        other => WireError::Protocol(other.to_string()),
    })?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_becomes_wss_and_http_becomes_ws() {
        assert_eq!(
            upgrade_url("https://fleet.example:7000", "/agent").unwrap(),
            "wss://fleet.example:7000/agent"
        );
        assert_eq!(
            upgrade_url("http://127.0.0.1:7000", "/client").unwrap(),
            "ws://127.0.0.1:7000/client"
        );
    }

    /// A bare `host:port` is what operators type and what the pre-revision-2
    /// config field held, so it must keep working — defaulting to TLS, never
    /// silently to plaintext.
    #[test]
    fn bare_host_port_defaults_to_wss() {
        assert_eq!(
            upgrade_url("fleet.example:7000", "/agent").unwrap(),
            "wss://fleet.example:7000/agent"
        );
    }

    #[test]
    fn trailing_slash_and_path_prefix_are_handled() {
        assert_eq!(
            upgrade_url("https://fleet.example/", "/agent").unwrap(),
            "wss://fleet.example/agent"
        );
        // Mounted under a sub-path of a reverse proxy.
        assert_eq!(
            upgrade_url("https://example.com/fleet", "/client").unwrap(),
            "wss://example.com/fleet/client"
        );
    }

    #[test]
    fn explicit_ws_schemes_pass_through() {
        assert_eq!(
            upgrade_url("wss://fleet.example", "/agent").unwrap(),
            "wss://fleet.example/agent"
        );
        assert_eq!(
            upgrade_url("ws://fleet.example", "/agent").unwrap(),
            "ws://fleet.example/agent"
        );
    }

    #[test]
    fn unusable_urls_are_rejected() {
        assert!(upgrade_url("", "/agent").is_err());
        assert!(upgrade_url("ftp://fleet.example", "/agent").is_err());
    }

    /// Both ends must agree on the message-size limit, so the dialer's config
    /// is derived from `MAX_FRAME_LEN` rather than from tungstenite's default.
    #[test]
    fn websocket_config_matches_the_wire_limit() {
        let cfg = websocket_config();
        assert_eq!(cfg.max_message_size, Some(MAX_FRAME_LEN));
        assert_eq!(cfg.max_frame_size, Some(MAX_FRAME_LEN));
    }
}
