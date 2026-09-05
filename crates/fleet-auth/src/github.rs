//! GitHub user login through the OAuth 2.0 **device flow** (RFC 8628), feature
//! `client`.
//!
//! # Why this is not an OIDC client
//!
//! GitHub's user-facing login is plain **OAuth 2.0 authorization**, not
//! `OpenID` Connect: there is no `.well-known/openid-configuration`, no ID
//! token, no
//! JWKS, and therefore nothing to validate a signature against. The device flow
//! hands back an *access token* and nothing else; the only way to learn *who*
//! authorised it is to spend it on `GET /user`. Reaching for an OIDC library
//! here would add a dependency that has no discovery document to fetch and no
//! token to verify — every line of it would be dead weight, and the "verified"
//! feeling it gives would be false.
//!
//! # Why the device flow rather than the redirect flow
//!
//! `fleet ctl login` runs on a terminal that may be an SSH session on a
//! headless box. The device flow needs no loopback listener and no registered
//! redirect URI: print a URL and a short code, let the human finish on whatever
//! machine has a browser, and poll.
//!
//! # Token handling
//!
//! [`poll_device_flow`] returning [`DevicePoll::Granted`] yields the **user's
//! GitHub access token**. That token is a credential for the user's GitHub
//! account, not for this fleet: it must never leave the coordinator process, is
//! never logged, and is never persisted. It exists only long enough to be
//! exchanged — via [`fetch_user`] — for a fleet session token, which is the
//! only credential that flows back to the client.
//!
//! # Layering
//!
//! Parsing is split out into pure `&[u8]` -> `Result<_, _>` functions
//! ([`parse_device_code_response`], [`parse_poll_response`],
//! [`parse_user_response`]) so the wire contract is unit-testable against
//! captured payloads with no network and no mock server.

use std::time::Duration;

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

/// How long a single GitHub request may take before it is abandoned.
///
/// The device flow is polled in a loop, so a hung request must not wedge the
/// login: the caller's next poll re-establishes the connection.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `User-Agent` sent on every request.
///
/// GitHub's API answers **403** to requests without a `User-Agent`, and the
/// token endpoints are hosted on the same edge, so it is sent on all three
/// requests rather than only on the API call.
const USER_AGENT: &str = concat!("probe-rs-fleet/", env!("CARGO_PKG_VERSION"));

/// Fallback lifetime for a device code when GitHub omits `expires_in`.
const DEFAULT_EXPIRES_IN: u64 = 900;

/// Fallback poll interval when GitHub omits `interval`.
const DEFAULT_INTERVAL: u64 = 5;

/// The three GitHub URLs the device flow touches.
///
/// Split out from [`GithubApp`] so tests and GitHub Enterprise Server
/// deployments (which serve the same protocol from a different origin) can
/// point the flow elsewhere without a second code path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubEndpoints {
    /// `POST` target that starts the flow and mints a device/user code pair.
    pub device_code_url: String,
    /// `POST` target that is polled until the user approves or the code dies.
    pub access_token_url: String,
    /// Origin of the REST API, without a trailing slash; `/user` is appended.
    pub api_base: String,
}

impl Default for GithubEndpoints {
    /// github.com's endpoints.
    ///
    /// Note the split origins: the OAuth endpoints live on `github.com` while
    /// the REST API lives on `api.github.com`. They are not interchangeable —
    /// posting the token request to the API origin returns a 404 that looks
    /// like a client-id problem.
    fn default() -> Self {
        Self {
            device_code_url: "https://github.com/login/device/code".to_owned(),
            access_token_url: "https://github.com/login/oauth/access_token".to_owned(),
            api_base: "https://api.github.com".to_owned(),
        }
    }
}

/// The registered GitHub application this coordinator logs users in as.
///
/// Constructed from coordinator configuration, then borrowed by every call in
/// this module: the flow is stateless apart from the device code, so there is
/// no client object to keep alive between polls.
#[derive(Clone)]
pub struct GithubApp {
    /// The OAuth app / GitHub App client id. Public by design.
    pub client_id: String,
    /// The client secret, if the registration requires one.
    ///
    /// Classic **OAuth Apps do not need a secret for the device flow** (the
    /// device code is the proof of possession), but some GitHub App
    /// configurations reject the token request without it, so it is optional
    /// rather than absent.
    pub client_secret: Option<String>,
    /// Space-separated scopes to request, e.g. `read:user user:email`.
    ///
    /// Empty means "no scope": the resulting token can still read public
    /// profile data, which is all [`fetch_user`] needs for identity.
    pub scope: String,
    /// Where to send the three requests.
    pub endpoints: GithubEndpoints,
}

impl std::fmt::Debug for GithubApp {
    /// Redacts the client secret.
    ///
    /// The coordinator logs its configuration on startup; a derived `Debug`
    /// would put the secret in the journal of every deployment.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubApp")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

/// The result of starting a device flow: what to show the user, and how to
/// poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCodeGrant {
    /// The secret half of the pair. Sent back on every poll, never shown to
    /// the user.
    pub device_code: String,
    /// The short code the user types into the browser. Show it verbatim,
    /// including the hyphen — GitHub's form expects that shape.
    pub user_code: String,
    /// The URL the user opens to enter [`Self::user_code`].
    pub verification_uri: String,
    /// Seconds until the device code expires; poll no longer than this.
    pub expires_in: u64,
    /// Minimum seconds between polls. Polling faster earns a `slow_down`.
    pub interval: u64,
}

/// One poll of the token endpoint.
///
/// Every *expected* device-flow outcome is a variant here rather than an error,
/// because "the user hasn't clicked yet" is the common case and callers must
/// not have to string-match on an error to keep looping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    /// The user has not finished authorising yet; sleep and poll again.
    Pending,
    /// The client polled too fast; wait at least this many seconds.
    SlowDown {
        /// The new minimum interval in seconds, as reported by GitHub.
        interval: u64,
    },
    /// The user (or an org policy) refused the request. Terminal.
    Denied,
    /// The device code expired before the user finished. Terminal; the caller
    /// must restart the flow with a fresh code.
    Expired,
    /// Authorisation succeeded.
    Granted {
        /// The user's GitHub access token. See the module docs: this must not
        /// leave the coordinator process.
        access_token: String,
    },
}

/// The subset of GitHub's `/user` payload that identifies a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUser {
    /// The immutable numeric account id — the only safe identity key.
    ///
    /// Logins can be changed by their owner and, once released, **re-registered
    /// by someone else**. Keying a fleet account off `login` would silently
    /// hand an old member's access to whoever grabs the freed name.
    pub id: u64,
    /// The current login (handle). Display only; may change over time.
    pub login: String,
    /// The account's public email, if it has one.
    ///
    /// Absent for the majority of users (GitHub hides it by default), so this
    /// can never be a required field.
    pub email: Option<String>,
}

/// Errors from the GitHub device flow.
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    /// A configured endpoint URL could not be parsed.
    #[error("invalid GitHub endpoint URL: {0}")]
    Url(String),
    /// The request could not be sent, timed out, or the body could not be read.
    #[error("GitHub transport error: {0}")]
    Transport(String),
    /// GitHub answered with a non-2xx status.
    ///
    /// Carries the body because GitHub's failure text (rate-limit notes, "Bad
    /// credentials") is the only actionable part, and it is *not* secret.
    #[error("GitHub returned HTTP {status}: {body}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The response body, truncated by GitHub, not by us.
        body: String,
    },
    /// The response was not the JSON shape this module expects.
    #[error("malformed GitHub response: {0}")]
    Malformed(String),
    /// GitHub reported an OAuth-level error that is not part of the normal
    /// device-flow state machine (e.g. `unsupported_grant_type`,
    /// `incorrect_client_credentials`).
    #[error("GitHub OAuth error `{code}`{}", .description.as_ref().map(|d| format!(": {d}")).unwrap_or_default())]
    Oauth {
        /// The machine-readable `error` field.
        code: String,
        /// The human-readable `error_description`, when present.
        description: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Form encoding
// ---------------------------------------------------------------------------

/// Percent-encode one `application/x-www-form-urlencoded` *value*.
///
/// Hand-rolled rather than pulled from `url`/`percent-encoding`: the agent has
/// to cross-compile to armv7-musl and the workspace deliberately keeps its
/// dependency graph small (see `http_client`'s notes on why `reqwest` is out).
/// Encoding a form value is a dozen lines; a new crate in the tree is forever.
///
/// Everything outside the unreserved set of RFC 3986 is escaped, which is
/// stricter than necessary but never wrong. Notably that covers the `:` in
/// `urn:ietf:params:oauth:grant-type:device_code` and the `&`/`=` that would
/// otherwise let an opaque GitHub-supplied value inject extra form fields.
///
/// Spaces become `%20` rather than `+`; both are accepted for form bodies, and
/// `%20` is the one that is also correct in a query string, so there is a
/// single rule to remember.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            other => {
                // Uppercase hex, written nibble-by-nibble: RFC 3986 says
                // producers should emit uppercase, and a table lookup avoids a
                // per-byte `format!` allocation in a hot-enough path.
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(other >> 4)]));
                out.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    out
}

/// Build a form body from already-known-good key names and opaque values.
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ---------------------------------------------------------------------------
// Parsing (pure, testable)
// ---------------------------------------------------------------------------

/// The device-code response, plus the error fields GitHub may return instead.
#[derive(Deserialize)]
struct DeviceCodeBody {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The token-endpoint response. Success and failure share one JSON object,
/// distinguished only by which fields are present.
#[derive(Deserialize)]
struct PollBody {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    interval: Option<u64>,
}

/// The `/user` payload, narrowed to the identity fields.
#[derive(Deserialize)]
struct UserBody {
    /// A JSON **number**. Declaring it `u64` makes a string-typed id a parse
    /// error rather than a silently different identity.
    id: u64,
    login: String,
    email: Option<String>,
}

/// Parse the body of a successful `POST /login/device/code`.
///
/// `expires_in` and `interval` are optional on the wire and default to 900 and
/// 5 seconds — GitHub's documented values — so a terse response still yields a
/// pollable grant instead of an error.
///
/// # Errors
///
/// Returns [`GithubError::Malformed`] if the body is not JSON or is missing a
/// required field, or [`GithubError::Oauth`] if GitHub returned an error object
/// (it does so with a 200 for e.g. an unknown `client_id`).
pub fn parse_device_code_response(body: &[u8]) -> Result<DeviceCodeGrant, GithubError> {
    let parsed: DeviceCodeBody =
        serde_json::from_slice(body).map_err(|e| GithubError::Malformed(e.to_string()))?;

    if let Some(code) = parsed.error {
        return Err(GithubError::Oauth {
            code,
            description: parsed.error_description,
        });
    }

    let missing = |field: &str| GithubError::Malformed(format!("missing `{field}`"));
    Ok(DeviceCodeGrant {
        device_code: parsed.device_code.ok_or_else(|| missing("device_code"))?,
        user_code: parsed.user_code.ok_or_else(|| missing("user_code"))?,
        verification_uri: parsed
            .verification_uri
            .ok_or_else(|| missing("verification_uri"))?,
        expires_in: parsed.expires_in.unwrap_or(DEFAULT_EXPIRES_IN),
        interval: parsed.interval.unwrap_or(DEFAULT_INTERVAL),
    })
}

/// Parse one token-endpoint response into a [`DevicePoll`].
///
/// The four documented device-flow error codes are *states*, not failures, and
/// map to variants. Anything else — a revoked app, a bad secret, a
/// typo'd grant type — is a real error the caller cannot poll its way out of,
/// so it surfaces as [`GithubError::Oauth`] and stops the loop.
///
/// # Errors
///
/// Returns [`GithubError::Malformed`] if the body is not JSON or contains
/// neither `access_token` nor `error`, and [`GithubError::Oauth`] for any error
/// code outside the device-flow state machine.
pub fn parse_poll_response(body: &[u8]) -> Result<DevicePoll, GithubError> {
    let parsed: PollBody =
        serde_json::from_slice(body).map_err(|e| GithubError::Malformed(e.to_string()))?;

    if let Some(access_token) = parsed.access_token {
        return Ok(DevicePoll::Granted { access_token });
    }

    let Some(code) = parsed.error else {
        return Err(GithubError::Malformed(
            "response has neither `access_token` nor `error`".to_owned(),
        ));
    };

    Ok(match code.as_str() {
        "authorization_pending" => DevicePoll::Pending,
        // GitHub sends the *new* minimum interval alongside `slow_down`. When
        // it does not, 5s is the documented increment to add to the previous
        // interval, and is also the floor we started from.
        "slow_down" => DevicePoll::SlowDown {
            interval: parsed.interval.unwrap_or(DEFAULT_INTERVAL),
        },
        "expired_token" => DevicePoll::Expired,
        "access_denied" => DevicePoll::Denied,
        _ => {
            return Err(GithubError::Oauth {
                code,
                description: parsed.error_description,
            })
        }
    })
}

/// Parse a `GET /user` response.
///
/// # Errors
///
/// Returns [`GithubError::Malformed`] if the body is not JSON with a numeric
/// `id` and a string `login`.
pub fn parse_user_response(body: &[u8]) -> Result<GithubUser, GithubError> {
    let parsed: UserBody =
        serde_json::from_slice(body).map_err(|e| GithubError::Malformed(e.to_string()))?;
    Ok(GithubUser {
        id: parsed.id,
        login: parsed.login,
        email: parsed.email,
    })
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Build the HTTPS client.
///
/// Deliberately the *same* stack and the *same* trust path as
/// [`crate::http_client`]: `hyper` + `hyper-rustls` with
/// [`fleet_tls::client_trust_config`]. `None` is passed for the pin because
/// github.com is always a public Web PKI certificate — the
/// `--server-cert-sha256` pin exists for self-hosted coordinators and pinning
/// GitHub's rotating leaf would break the login on every renewal.
fn https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let tls = fleet_tls::client_trust_config(None);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Send a prepared request and collect `(status, body)`.
///
/// The status is returned rather than turned into an error here, because the
/// device flow's meaning of "200" is caller-specific: the token endpoint
/// reports authorisation failures *inside* a 200 body.
async fn send(req: http::Request<Full<Bytes>>) -> Result<(u16, Vec<u8>), GithubError> {
    let client = https_client();
    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(req))
        .await
        .map_err(|_| GithubError::Transport("GitHub request timed out".to_owned()))?
        .map_err(|e| GithubError::Transport(e.to_string()))?;

    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| GithubError::Transport(e.to_string()))?
        .to_bytes();
    Ok((status, bytes.to_vec()))
}

/// `POST` a form-encoded body to one of the github.com OAuth endpoints.
///
/// `Accept: application/json` is **mandatory**: without it GitHub answers the
/// token endpoints with an `application/x-www-form-urlencoded` body, which
/// `serde_json` would reject with a confusing "expected value" error.
///
/// Takes no [`GithubApp`]: the only per-app input is already baked into `form`,
/// and the `User-Agent` is a crate-wide constant.
async fn post_form(url: &str, form: String) -> Result<(u16, Vec<u8>), GithubError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| GithubError::Url(e.to_string()))?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::USER_AGENT, USER_AGENT)
        .body(Full::new(Bytes::from(form)))
        .map_err(|e| GithubError::Transport(e.to_string()))?;
    send(req).await
}

/// `GET` a JSON resource from the REST API with a bearer access token.
///
/// `Accept: application/vnd.github+json` selects the current API media type;
/// omitting it leaves the response shape at GitHub's discretion.
async fn get_json(url: &str, bearer: &str) -> Result<(u16, Vec<u8>), GithubError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| GithubError::Url(e.to_string()))?;
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .header(http::header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(http::header::ACCEPT, "application/vnd.github+json")
        .header(http::header::USER_AGENT, USER_AGENT)
        .body(Full::new(Bytes::new()))
        .map_err(|e| GithubError::Transport(e.to_string()))?;
    send(req).await
}

/// Render a response body for an error message.
///
/// Bodies from these endpoints are GitHub's own diagnostics, never user
/// secrets, so echoing them is safe and is usually the only clue an operator
/// gets.
fn body_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

/// Start a device flow: ask GitHub for a device/user code pair.
///
/// The caller shows [`DeviceCodeGrant::user_code`] and
/// [`DeviceCodeGrant::verification_uri`] to the human, then polls
/// [`poll_device_flow`] no faster than [`DeviceCodeGrant::interval`].
///
/// # Errors
///
/// Returns [`GithubError`] on a transport failure, a non-2xx status, an OAuth
/// error object, or a body that is not a device-code response.
pub async fn start_device_flow(app: &GithubApp) -> Result<DeviceCodeGrant, GithubError> {
    // An empty `scope` is omitted rather than sent as `scope=`: GitHub treats
    // the empty string as a request for no scopes either way, but omitting it
    // keeps the body identical to the documented example.
    let mut pairs = vec![("client_id", app.client_id.as_str())];
    if !app.scope.is_empty() {
        pairs.push(("scope", app.scope.as_str()));
    }

    let (status, body) = post_form(&app.endpoints.device_code_url, form_body(&pairs)).await?;
    if !(200..300).contains(&status) {
        return Err(GithubError::Http {
            status,
            body: body_text(&body),
        });
    }
    parse_device_code_response(&body)
}

/// Poll the token endpoint once for the given device code.
///
/// Call this on a timer; it performs exactly one request and never sleeps, so
/// the caller owns the backoff and the overall deadline
/// ([`DeviceCodeGrant::expires_in`]).
///
/// GitHub reports device-flow errors **with HTTP 200** and an `error` field, so
/// a 2xx body is always parsed rather than assumed successful; only a genuine
/// non-2xx becomes [`GithubError::Http`].
///
/// # Errors
///
/// Returns [`GithubError`] on a transport failure, a non-2xx status, a
/// malformed body, or an OAuth error code outside the device-flow state
/// machine (see [`parse_poll_response`]).
pub async fn poll_device_flow(
    app: &GithubApp,
    device_code: &str,
) -> Result<DevicePoll, GithubError> {
    let mut pairs = vec![
        ("client_id", app.client_id.as_str()),
        ("device_code", device_code),
        // The grant type is a URN full of `:`, which is exactly why form values
        // are percent-encoded rather than concatenated.
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
    ];
    // Only sent when configured: OAuth Apps must *not* need it for the device
    // flow, while some GitHub App registrations refuse the request without it.
    if let Some(secret) = app.client_secret.as_deref() {
        pairs.push(("client_secret", secret));
    }

    let (status, body) = post_form(&app.endpoints.access_token_url, form_body(&pairs)).await?;
    if !(200..300).contains(&status) {
        return Err(GithubError::Http {
            status,
            body: body_text(&body),
        });
    }
    parse_poll_response(&body)
}

/// Resolve an access token to the GitHub account that authorised it.
///
/// This is the identity step the device flow itself cannot provide: the access
/// token is opaque and unsigned, so the only authority on who it belongs to is
/// GitHub.
///
/// # Errors
///
/// Returns [`GithubError`] on a transport failure, a non-2xx status (401 for a
/// revoked or mistyped token, 403 for a missing `User-Agent` or a rate limit),
/// or a body that is not a user object.
pub async fn fetch_user(app: &GithubApp, access_token: &str) -> Result<GithubUser, GithubError> {
    let base = app.endpoints.api_base.trim_end_matches('/');
    let (status, body) = get_json(&format!("{base}/user"), access_token).await?;
    if !(200..300).contains(&status) {
        return Err(GithubError::Http {
            status,
            body: body_text(&body),
        });
    }
    parse_user_response(&body)
}

/// Fetch a **GitHub Actions workload identity token** from the runner's own
/// token service (architecture §6.7).
///
/// This is the other half of the sentence this module opens with. User login is
/// plain `OAuth2` with nothing to verify; a *workload* identity is real OIDC —
/// a signed JWT with a JWKS behind it — and this is where a CI job obtains one.
///
/// `url` and `request_token` come from `ACTIONS_ID_TOKEN_REQUEST_URL` /
/// `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which the runner injects **only** for a
/// job carrying `permissions: id-token: write`. Both are per-job credentials
/// the runner already holds; nothing is stored and nothing outlives the job.
///
/// It lives here rather than in `fleet-bin` for the reason
/// [`crate::http_client`]'s docs give about forking trust paths: this request
/// and the `/auth/token` exchange that follows it must go through the same
/// `hyper` + `hyper-rustls` stack, or one of them silently stops honouring the
/// workspace's TLS decisions.
///
/// # Errors
///
/// Returns [`GithubError`] on a transport failure, a non-2xx status (the usual
/// cause being a job without `id-token: write`), a body with no `value` field,
/// or an `audience` carrying query metacharacters — refused rather than
/// escaped, because a fleet URL containing `&` is a configuration mistake and
/// not something to paper over.
pub async fn fetch_workload_id_token(
    url: &str,
    request_token: &str,
    audience: &str,
) -> Result<String, GithubError> {
    #[derive(Deserialize)]
    struct IdTokenResponse {
        value: String,
    }

    if audience.trim().is_empty() || audience.contains('&') || audience.contains('#') {
        return Err(GithubError::Url(
            "audience must be non-empty and free of `&` and `#`".to_owned(),
        ));
    }
    let separator = if url.contains('?') { '&' } else { '?' };
    let full = format!("{url}{separator}audience={}", percent_encode(audience));
    let (status, body) = get_json(&full, request_token).await?;
    if !(200..300).contains(&status) {
        return Err(GithubError::Http {
            status,
            body: body_text(&body),
        });
    }

    let parsed: IdTokenResponse = serde_json::from_slice(&body)
        .map_err(|e| GithubError::Malformed(format!("OIDC token response: {e}")))?;
    if parsed.value.trim().is_empty() {
        return Err(GithubError::Malformed(
            "OIDC token response carried an empty `value`".to_owned(),
        ));
    }
    Ok(parsed.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_code_response_parses() {
        // Captured from github.com; field order and the hyphenated user code
        // are reproduced verbatim.
        let body = br#"{
            "device_code": "3584d83530557fdd1f46af8289938c8ef79f9dc5",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 899,
            "interval": 5
        }"#;
        let grant = parse_device_code_response(body).unwrap();
        assert_eq!(
            grant.device_code,
            "3584d83530557fdd1f46af8289938c8ef79f9dc5"
        );
        assert_eq!(grant.user_code, "WDJB-MJHT");
        assert_eq!(grant.verification_uri, "https://github.com/login/device");
        assert_eq!(grant.expires_in, 899);
        assert_eq!(grant.interval, 5);
    }

    #[test]
    fn device_code_defaults_fill_in_absent_timings() {
        let body = br#"{
            "device_code": "dc",
            "user_code": "AAAA-BBBB",
            "verification_uri": "https://github.com/login/device"
        }"#;
        let grant = parse_device_code_response(body).unwrap();
        assert_eq!(grant.expires_in, DEFAULT_EXPIRES_IN);
        assert_eq!(grant.interval, DEFAULT_INTERVAL);
    }

    #[test]
    fn device_code_error_object_is_an_oauth_error() {
        // GitHub reports an unknown client id with HTTP 200 and this body.
        let body = br#"{"error":"unauthorized_client","error_description":"nope"}"#;
        let err = parse_device_code_response(body).unwrap_err();
        assert!(
            matches!(err, GithubError::Oauth { ref code, .. } if code == "unauthorized_client")
        );
    }

    #[test]
    fn poll_success_maps_to_granted() {
        let body = br#"{
            "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
            "token_type": "bearer",
            "scope": "read:user"
        }"#;
        assert_eq!(
            parse_poll_response(body).unwrap(),
            DevicePoll::Granted {
                access_token: "gho_16C7e42F292c6912E7710c838347Ae178B4a".to_owned()
            }
        );
    }

    #[test]
    fn poll_error_codes_map_to_states() {
        let cases: [(&[u8], DevicePoll); 4] = [
            (
                br#"{"error":"authorization_pending","error_description":"..."}"#,
                DevicePoll::Pending,
            ),
            (
                br#"{"error":"slow_down","interval":10}"#,
                DevicePoll::SlowDown { interval: 10 },
            ),
            (br#"{"error":"expired_token"}"#, DevicePoll::Expired),
            (br#"{"error":"access_denied"}"#, DevicePoll::Denied),
        ];
        for (body, expected) in cases {
            assert_eq!(parse_poll_response(body).unwrap(), expected);
        }
    }

    #[test]
    fn slow_down_without_an_interval_falls_back_to_the_floor() {
        assert_eq!(
            parse_poll_response(br#"{"error":"slow_down"}"#).unwrap(),
            DevicePoll::SlowDown {
                interval: DEFAULT_INTERVAL
            }
        );
    }

    #[test]
    fn unknown_error_code_is_not_a_poll_state() {
        // Anything outside the device-flow state machine must stop the loop
        // rather than be mistaken for "keep waiting".
        let err = parse_poll_response(br#"{"error":"incorrect_client_credentials"}"#).unwrap_err();
        match err {
            GithubError::Oauth { code, description } => {
                assert_eq!(code, "incorrect_client_credentials");
                assert!(description.is_none());
            }
            other => panic!("expected an OAuth error, got {other:?}"),
        }
    }

    #[test]
    fn poll_body_without_token_or_error_is_malformed() {
        assert!(matches!(
            parse_poll_response(br#"{"token_type":"bearer"}"#).unwrap_err(),
            GithubError::Malformed(_)
        ));
    }

    #[test]
    fn user_response_parses_numeric_id() {
        // `id` is a JSON *number*. Identity keys off it and never off `login`:
        // GitHub logins can be renamed by their owner and the freed name can be
        // re-registered by a different person, so a login-keyed account would
        // hand a departed member's access to a stranger.
        let body = br#"{
            "login": "octocat",
            "id": 583231,
            "node_id": "MDQ6VXNlcjU4MzIzMQ==",
            "email": "octocat@github.com",
            "type": "User"
        }"#;
        let user = parse_user_response(body).unwrap();
        assert_eq!(user.id, 583_231);
        assert_eq!(user.login, "octocat");
        assert_eq!(user.email.as_deref(), Some("octocat@github.com"));

        // Same account after a rename: the id is unchanged, so identity holds.
        let renamed = br#"{"login": "monalisa", "id": 583231, "email": null}"#;
        let user2 = parse_user_response(renamed).unwrap();
        assert_eq!(user2.id, user.id);
        assert_ne!(user2.login, user.login);
        assert!(user2.email.is_none());
    }

    #[test]
    fn user_id_as_a_string_is_rejected() {
        // A string id would compare unequal to the stored numeric one; failing
        // loudly beats creating a duplicate account.
        assert!(matches!(
            parse_user_response(br#"{"login":"octocat","id":"583231"}"#).unwrap_err(),
            GithubError::Malformed(_)
        ));
    }

    #[test]
    fn percent_encoder_escapes_form_metacharacters() {
        assert_eq!(
            percent_encode("urn:ietf:params:oauth:grant-type:device_code"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            percent_encode("read:user user:email"),
            "read%3Auser%20user%3Aemail"
        );
        // Unreserved characters must survive untouched, or the device code
        // would be corrupted on the way back to GitHub.
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn form_body_joins_pairs() {
        assert_eq!(
            form_body(&[("client_id", "Iv1.abc"), ("scope", "read:user")]),
            "client_id=Iv1.abc&scope=read%3Auser"
        );
    }
}
