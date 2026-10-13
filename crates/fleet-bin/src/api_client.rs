//! A minimal `GET` for the coordinator's own JSON routes, over the same trust
//! path as [`forgs_client::ForgsClient`].
//!
//! `ForgsClient` only exposes `POST` for app routes, and `probe-rs-fleet org
//! list` needs `GET /api/v1/session` (bearer-accepted, and it already returns
//! memberships with names and roles). This mirrors `forgs-client`'s transport:
//! the same TLS config ([`forgs_client::tls::client_trust_config`], so a
//! certificate pin applies), the same absolute-path route guard, a 30 s
//! deadline and a 1 MiB body cap, and a non-2xx mapped to
//! [`ClientError::Rejected`] with the server's `{error}` code. If forgs grows a
//! `get_json`, swap it in.

use std::time::Duration;

use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;

use forgs_client::{normalise_base, ClientError, Secret};

/// End-to-end budget for one request.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response body read.
const MAX_BODY: usize = 1024 * 1024;

/// `{base}{route}`, refusing a `route` that is not an absolute path — anything
/// else could splice into the authority and send the bearer elsewhere.
fn uri(base: &str, route: &str) -> Result<http::Uri, ClientError> {
    if !route.starts_with('/')
        || route.starts_with("//")
        || route.contains("://")
        || route.contains('#')
        || route.bytes().any(|b| b.is_ascii_control() || b == b' ')
    {
        return Err(ClientError::Url(format!(
            "route must be an absolute path: {route:?}"
        )));
    }
    format!("{}{route}", normalise_base(base)?)
        .parse()
        .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))
}

/// `GET {base}{route}` with an optional bearer, decoding a JSON body.
///
/// # Errors
///
/// [`ClientError::Url`] for a bad base or route (nothing is sent),
/// [`ClientError::Transport`] if the server was not reached or timed out,
/// [`ClientError::Rejected`] for a non-2xx, [`ClientError::Malformed`] for a
/// body that does not decode as `R`.
pub async fn get_json<R: DeserializeOwned>(
    base: &str,
    pin: Option<[u8; 32]>,
    bearer: Option<&Secret>,
    route: &str,
) -> Result<R, ClientError> {
    let uri = uri(base, route)?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(forgs_client::tls::client_trust_config(pin))
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let mut builder = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .header(http::header::ACCEPT, "application/json");
    if let Some(bearer) = bearer {
        let mut value = http::HeaderValue::from_str(&format!("Bearer {}", bearer.expose()))
            .map_err(|_| ClientError::Url("credential is not a valid header value".to_owned()))?;
        value.set_sensitive(true);
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    let req = builder
        .body(Empty::new())
        .map_err(|e| ClientError::Transport(e.to_string()))?;
    let exchange = async {
        let resp = client
            .request(req)
            .await
            .map_err(|e| ClientError::Transport(describe(&e)))?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| ClientError::Transport(format!("reading the response: {e}")))?
            .to_bytes();
        Ok::<_, ClientError>((status, body))
    };
    let (status, body) = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| ClientError::Transport("request timed out".to_owned()))??;
    if !status.is_success() {
        let code = serde_json::from_slice::<forgs::api::ErrorResponse>(&body)
            .map_or_else(|_| "unknown".to_owned(), |e| e.error);
        return Err(ClientError::Rejected {
            status: status.as_u16(),
            code,
        });
    }
    // The decode error is classified, never quoted: a body may carry a token.
    serde_json::from_slice(&body).map_err(|e| {
        ClientError::Malformed(format!(
            "{route}: {:?} error at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        ))
    })
}

/// The cause chain of a hyper-util error (the top level says only
/// "client error (Connect)").
fn describe(e: &hyper_util::client::legacy::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_absolute_paths_are_routes() {
        assert!(uri("https://fleet.example", "/api/v1/session").is_ok());
        for bad in [
            "api/v1/session",
            "@evil.example/x",
            "//evil.example/x",
            "/x#frag",
            "/a b",
            "/x\n",
            "https://evil.example/x",
        ] {
            assert!(
                matches!(uri("https://fleet.example", bad), Err(ClientError::Url(_))),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn the_base_is_normalised() {
        let u = uri("fleet.example:7000", "/api/v1/session").unwrap();
        assert_eq!(u.to_string(), "https://fleet.example:7000/api/v1/session");
    }
}
