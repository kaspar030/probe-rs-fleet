//! The HTTP client for `POST /auth/token` (feature `client`).
//!
//! `share`, `agent up --auth-key` and a session-token refresh each need to make
//! exactly one HTTP request, and `agent up` runs on the Pi — so this stack is inside the
//! hard cross-compilation constraint that forced `ring` over `aws-lc-rs`.
//!
//! # Why hyper rather than reqwest
//!
//! Both cross-build to a static armv7-musl binary with zero `aws-lc-rs` (see
//! `docs/cross-compiling.md`). `reqwest` pulls ~37 crates nothing else in the
//! workspace needs, including `url` → `idna` → the `icu_*` unicode stack. The
//! `hyper` route reuses `hyper` / `hyper-util` / `rustls` / `http`, which the
//! coordinator and `tokio-tungstenite` already require.
//!
//! The deciding property, though, is trust: [`hyper_rustls`]'s
//! `with_tls_config` takes an explicitly-built [`rustls::ClientConfig`], so the
//! token exchange and the WebSocket dialer share
//! [`fleet_tls::client_trust_config`]. **Keep that single trust path.** If it
//! forks, `--server-cert-sha256` silently stops covering `/auth/token` while
//! appearing to work.

use std::time::Duration;

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::api::{
    DevicePollRequest, DeviceStartRequest, DeviceStartResponse, ErrorResponse, TokenRequest,
    TokenResponse,
};

/// How long a token exchange may take before it is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors from a token exchange.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The base URL could not be parsed / had no host.
    #[error("invalid coordinator URL: {0}")]
    Url(String),
    /// The request could not be sent or the response could not be read.
    #[error("token exchange transport error: {0}")]
    Transport(String),
    /// The coordinator rejected the exchange.
    ///
    /// Deliberately coarse, because the response body is deliberately coarse.
    /// The remediation text belongs to the caller, which knows what it was
    /// trying to do.
    #[error("token exchange rejected by the coordinator ({status}): {code}")]
    Rejected {
        /// The HTTP status.
        status: u16,
        /// The machine-readable error code from the body, or `unknown`.
        code: String,
    },
    /// The response was not the JSON we expect.
    #[error("malformed token exchange response: {0}")]
    Malformed(String),
}

/// Build the `/auth/token` URI from a coordinator base URL.
fn token_uri(base_url: &str) -> Result<http::Uri, ClientError> {
    route_uri(base_url, "/auth/token")
}

/// Build a coordinator URI for `route` (which must start with `/`).
fn route_uri(base_url: &str, route: &str) -> Result<http::Uri, ClientError> {
    let normalised = normalise_base(base_url)?;
    format!("{normalised}{route}")
        .parse::<http::Uri>()
        .map_err(|e| ClientError::Url(e.to_string()))
}

/// Normalise a user-supplied coordinator address into an `http(s)://host[:port]`
/// origin with no trailing slash.
///
/// Accepts a bare `host:port` (defaulting to `https`), matching what the WS
/// dialer accepts, so an operator can paste the same string into both.
///
/// # Errors
///
/// Returns [`ClientError::Url`] if the string is not a usable origin.
pub fn normalise_base(base_url: &str) -> Result<String, ClientError> {
    let s = base_url.trim();
    if s.is_empty() {
        return Err(ClientError::Url("empty URL".to_owned()));
    }
    // No trailing-slash trim here: the origin is rebuilt from the parsed
    // scheme/authority/path below, so `https://x/` and `https://x` converge
    // without a textual hack that would turn `https://` into `https:`.
    let with_scheme = if s.contains("://") {
        s.to_owned()
    } else {
        format!("https://{s}")
    };
    let uri: http::Uri = with_scheme
        .parse()
        .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    if scheme != "http" && scheme != "https" {
        return Err(ClientError::Url(format!("unsupported scheme `{scheme}`")));
    }
    let authority = uri
        .authority()
        .filter(|a| !a.host().is_empty())
        .ok_or_else(|| ClientError::Url("URL has no host".to_owned()))?;
    let path = uri.path().trim_end_matches('/');
    Ok(format!("{scheme}://{authority}{path}"))
}

/// POST a [`TokenRequest`] to `<base_url>/auth/token`.
///
/// `pin` is the optional server-cert SHA-256 for self-hosted deployments; it is
/// threaded into the *same* [`fleet_tls::client_trust_config`] the WebSocket
/// dialer uses.
///
/// # Errors
///
/// Returns [`ClientError`] on a transport failure, a non-2xx response, or a body
/// that is not a [`TokenResponse`].
pub async fn exchange(
    base_url: &str,
    pin: Option<[u8; 32]>,
    request: &TokenRequest,
) -> Result<TokenResponse, ClientError> {
    post_json(&token_uri(base_url)?, pin, request).await
}

/// POST `request` as JSON to `uri` and decode the response as `R`.
///
/// Shared by `/auth/token` and the two `/auth/device/*` routes so all three go
/// through one trust path, one timeout and one error mapping.
async fn post_json<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    uri: &http::Uri,
    pin: Option<[u8; 32]>,
    request: &Q,
) -> Result<R, ClientError> {
    let body = serde_json::to_vec(request)
        .map_err(|e| ClientError::Malformed(format!("encoding request: {e}")))?;

    let tls = fleet_tls::client_trust_config(pin);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri.clone())
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| ClientError::Transport(e.to_string()))?;

    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(req))
        .await
        .map_err(|_| ClientError::Transport("token exchange timed out".to_owned()))?
        .map_err(|e| ClientError::Transport(e.to_string()))?;

    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?
        .to_bytes();

    if !status.is_success() {
        let code = serde_json::from_slice::<ErrorResponse>(&bytes)
            .map_or_else(|_| "unknown".to_owned(), |e| e.error);
        return Err(ClientError::Rejected {
            status: status.as_u16(),
            code,
        });
    }

    serde_json::from_slice(&bytes).map_err(|e| ClientError::Malformed(e.to_string()))
}

/// Redeem an auth key for a node token.
///
/// # Errors
///
/// See [`exchange`].
pub async fn exchange_auth_key(
    base_url: &str,
    pin: Option<[u8; 32]>,
    auth_key: &str,
    node_name: &str,
    tags: Vec<String>,
) -> Result<TokenResponse, ClientError> {
    exchange(
        base_url,
        pin,
        &TokenRequest::AuthKey {
            auth_key: auth_key.to_owned(),
            node_name: node_name.to_owned(),
            tags,
        },
    )
    .await
}

/// Exchange a still-valid session token for a fresh one.
///
/// # Errors
///
/// See [`exchange`].
pub async fn refresh_session(
    base_url: &str,
    pin: Option<[u8; 32]>,
    session_token: &str,
) -> Result<TokenResponse, ClientError> {
    exchange(
        base_url,
        pin,
        &TokenRequest::Refresh {
            session_token: session_token.to_owned(),
        },
    )
    .await
}

/// Register this machine as a node in the caller's own org, proving
/// membership with a user session token (architecture §4.2 path 2).
///
/// This is the request `probe-rs-fleet share` makes: no auth key, no
/// coordinator shell, no out-of-band step. The returned node token is a
/// *distinct* credential from the session token that authorised it — see
/// `fleet-bin`'s `fleet_config` for why the two never merge.
///
/// `adopt` is the node's probe-adoption policy (`"auto"` | `"declared"`);
/// `None` lets the coordinator apply this grant's default (`auto`).
///
/// # Errors
///
/// See [`exchange`]. A caller who is not a member of the org their session
/// authenticated into is refused with `403 forbidden`.
pub async fn self_register(
    base_url: &str,
    pin: Option<[u8; 32]>,
    session_token: &str,
    node_name: &str,
    tags: Vec<String>,
    adopt: Option<&str>,
) -> Result<TokenResponse, ClientError> {
    exchange(
        base_url,
        pin,
        &TokenRequest::SelfRegister {
            session_token: session_token.to_owned(),
            node_name: node_name.to_owned(),
            tags,
            adopt: adopt.map(ToOwned::to_owned),
        },
    )
    .await
}

/// Ask the coordinator to begin a GitHub device flow on our behalf.
///
/// The CLI never talks to GitHub: the OAuth app's client id (and secret, if any)
/// stay server-side, and the user's *GitHub* access token never leaves the
/// coordinator — only a fleet session token comes back. A consequence worth the
/// trade: a self-hosted coordinator can use its own OAuth app without anybody
/// rebuilding this binary.
///
/// # Errors
///
/// See [`exchange`]. A coordinator with no `[github]` table answers `503` with
/// code `device_flow_unconfigured`, surfaced as [`ClientError::Rejected`].
pub async fn device_start(
    base_url: &str,
    pin: Option<[u8; 32]>,
) -> Result<DeviceStartResponse, ClientError> {
    post_json(
        &route_uri(base_url, "/auth/device/start")?,
        pin,
        &DeviceStartRequest::default(),
    )
    .await
}

/// Poll the coordinator for the outcome of a device flow.
///
/// Pending / rate-limit / expiry / denial all arrive as
/// [`ClientError::Rejected`] carrying GitHub's own code
/// (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`), so
/// the caller can drive its poll loop by matching on `code`.
///
/// # Errors
///
/// See [`exchange`].
pub async fn device_poll(
    base_url: &str,
    pin: Option<[u8; 32]>,
    device_code: &str,
) -> Result<TokenResponse, ClientError> {
    post_json(
        &route_uri(base_url, "/auth/device/poll")?,
        pin,
        &DevicePollRequest {
            device_code: device_code.to_owned(),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_port_defaults_to_https() {
        assert_eq!(
            normalise_base("fleet.example:7000").unwrap(),
            "https://fleet.example:7000"
        );
    }

    #[test]
    fn explicit_scheme_and_trailing_slash_are_preserved_and_trimmed() {
        assert_eq!(
            normalise_base("http://127.0.0.1:7000/").unwrap(),
            "http://127.0.0.1:7000"
        );
        assert_eq!(
            normalise_base("https://fleet.example").unwrap(),
            "https://fleet.example"
        );
    }

    #[test]
    fn token_uri_appends_the_route() {
        assert_eq!(
            token_uri("https://fleet.example:7000").unwrap().to_string(),
            "https://fleet.example:7000/auth/token"
        );
    }

    #[test]
    fn device_routes_share_the_base_normalisation() {
        assert_eq!(
            route_uri("fleet.example:7000/", "/auth/device/start")
                .unwrap()
                .to_string(),
            "https://fleet.example:7000/auth/device/start"
        );
        assert_eq!(
            route_uri("http://127.0.0.1:7000", "/auth/device/poll")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:7000/auth/device/poll"
        );
    }

    #[test]
    fn unusable_urls_are_rejected() {
        assert!(normalise_base("").is_err());
        assert!(normalise_base("ftp://fleet.example").is_err());
        assert!(normalise_base("https://").is_err());
    }
}
