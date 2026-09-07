//! Browser session authentication: cookies, CSRF, and the two login flows
//! (`docs/web-ui.md` D1).
//!
//! This module exists because a browser cannot hold an `Authorization: Bearer`
//! header the way `ctl` does. It adds **one extra carrier** for the credential
//! the coordinator already issues — the `prfs1_` session token in the `session`
//! table — and nothing else: no second credential kind, no second token table,
//! no second `Subject` construction site. [`crate::http::authenticate_request`]
//! stays the only place a `Subject` is built from wire input; this module hands
//! it a cookie value when the route allows one.
//!
//! # What is here
//!
//! | route | what |
//! |---|---|
//! | `GET /auth/github/start` | 302 to GitHub's authorize endpoint |
//! | `GET /auth/github/callback` | exchange the code, mint a session, set cookies, 302 `/ui` |
//! | `POST /api/v1/session/device/start` | the device fallback, `device_code` in a cookie |
//! | `POST /api/v1/session/device/poll` | the device fallback, session token in a cookie |
//!
//! `GET /api/v1/auth/methods` lives in [`crate::api`] with the rest of the JSON
//! surface; the config predicate it reports is [`login_method`] here.
//!
//! # Cookies
//!
//! Two, set together and cleared together:
//!
//! * `prfs_session` — the session token. `HttpOnly`, so JavaScript cannot read
//!   it and a single XSS cannot exfiltrate a credential that power-cycles real
//!   hardware. This is the whole trade `docs/web-ui.md` D1 takes, and the CSRF
//!   machinery below is its price.
//! * `prfs_csrf` — the double-submit token, deliberately **not** `HttpOnly`:
//!   the page has to read it to echo it in `X-Fleet-Csrf`.
//!
//! `Max-Age` on both tracks the `session` row's `expires`, so the browser never
//! holds a cookie the database has already forgotten.
//!
//! **`Secure` is unconditional.** Browsers treat `http://localhost` and
//! `http://127.0.0.1` as secure contexts, so the example config's
//! `http://127.0.0.1:7000` still works; any *other* plain-HTTP deployment is
//! unsupported for the UI rather than silently downgraded. Please do not make
//! this conditional on the scheme — that is the obvious "fix" and it would hand
//! every session to anyone on the path.
//!
//! # CSRF
//!
//! `prfs_csrf = hex(HMAC-SHA256(k, session_token_hash))` with
//! `k = HMAC-SHA256(<ed25519 signing seed>, "probe-rs-fleet/csrf/v1")`. Derived
//! from the coordinator's existing signing seed, **never** from a per-process
//! random: a per-process key logs every open tab out on every restart, and the
//! first implementer to hit that would "fix" it by persisting a second secret.
//! Rotating the signing seed invalidates open tabs, which is correct and is
//! already true of every capability token.
//!
//! [`csrf_ok`] is the one enforcement point: any request whose method is not
//! `GET`/`HEAD` **and** whose credential arrived by cookie must carry a
//! matching `X-Fleet-Csrf`. A bearer-authenticated `/api/v1` call needs no
//! header — the credential is not ambient, so there is nothing to forge. The
//! coordinator emits **no CORS headers anywhere**, which is what makes the
//! mandatory custom header a second, independent control: a custom header
//! cannot be sent cross-origin without a preflight, and the preflight fails.
//!
//! # The authorization-code flow, and what actually protects it
//!
//! `GET /auth/github/start` sends the PKCE parameters, and they protect
//! nothing here: **GitHub's OAuth app implementation ignores
//! `code_challenge`/`code_verifier`.** They are sent because they are harmless
//! and correct for a GHES or other-IdP future; writing "PKCE protects this"
//! would be false. What protects the callback is the `state` value bound to a
//! short-lived `HttpOnly` cookie, plus the `client_secret` — which is therefore
//! effectively **required** once browser login is enabled, unlike the device
//! flow. [`fleet_auth::github`]'s module documentation records the same.
//!
//! **`redirect_uri` is derived from `public_url`, never from the request.** Not
//! `Host`, not `X-Forwarded-Host`. The coordinator runs behind a reverse proxy
//! and does not see its own public name; a Host-derived callback is a
//! host-header-injection route to an attacker-controlled OAuth redirect, i.e.
//! an account takeover (`docs/web-ui.md` D1, §5).
//!
//! # The device fallback, and why it is not `/auth/device/*`
//!
//! `/auth/device/{start,poll}` return the `device_code` and then the session
//! token **in the response body**, i.e. to JavaScript — precisely the exposure
//! D1 rejects. The two `/api/v1/session/device/*` routes here are the same
//! stateless brokering with both secrets moved into `HttpOnly` cookies:
//! `/start` returns only `{user_code, verification_uri, interval, expires_in}`
//! and `/poll` only `{"status":"pending"|"ok"}`. The CLI's routes are
//! **unchanged** — no deployed behaviour moves.
//!
//! No new table: the device code still round-trips through the client (in a
//! cookie rather than a JSON field), so a coordinator restart mid-login is
//! still survivable, exactly as for the CLI flow.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Mac as _, SimpleHmac};
use serde::Serialize;
use sha2::Sha256;
use tracing::{info, warn};

use fleet_auth::github::{self, DevicePoll};
use fleet_auth::OpaqueToken;

use crate::config::SigningKeySource;
use crate::core::Coordinator;
use crate::http::{github_app, mint_session_for_user, reject};
use crate::state::AuditEntry;

/// The cookie carrying the `prfs1_` session token.
pub(crate) const SESSION_COOKIE: &str = "prfs_session";
/// The cookie carrying the double-submit CSRF token.
pub(crate) const CSRF_COOKIE: &str = "prfs_csrf";
/// The cookie holding an in-flight authorization-code flow's `state` and PKCE
/// verifier.
const OAUTH_COOKIE: &str = "prfs_oauth";
/// The cookie holding an in-flight device-fallback flow's `device_code`.
const DEVICE_COOKIE: &str = "prfs_device";
/// The header the UI echoes `prfs_csrf` in on every mutating call.
pub(crate) const CSRF_HEADER: &str = "x-fleet-csrf";

/// The fixed callback path. Not configurable: it is appended to `public_url`,
/// and an operator who could change it would have two things to keep in sync
/// with the OAuth app registration instead of one.
pub(crate) const CALLBACK_PATH: &str = "/auth/github/callback";

/// How long (seconds) an in-flight login's cookie lives.
///
/// Long enough to authorise at GitHub with a password manager and a second
/// factor, short enough that an abandoned flow does not leave a usable `state`
/// lying in the browser.
const LOGIN_FLOW_TTL_SECS: i64 = 600;

/// Domain separation for the CSRF key. Versioned so a future derivation change
/// is a new label rather than a silent reinterpretation of the same bytes.
const CSRF_LABEL: &[u8] = b"probe-rs-fleet/csrf/v1";

/// Which browser login this deployment offers, as reported by
/// `GET /api/v1/auth/methods`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginMethod {
    /// GitHub authorization-code: a `[github]` table with the callback
    /// registered.
    AuthorizationCode,
    /// A `[github]` table without the callback registration: the in-page
    /// device-code login, uglier but working.
    Device,
    /// No `[github]` table at all. A supported deployment (air-gapped, or
    /// development); it bootstraps with `coordinator user-token` and the UI has
    /// no login to offer.
    None,
}

impl LoginMethod {
    /// The wire label.
    fn as_str(self) -> &'static str {
        match self {
            LoginMethod::AuthorizationCode => "authorization_code",
            LoginMethod::Device => "device",
            LoginMethod::None => "none",
        }
    }
}

/// Which login this coordinator offers, from configuration alone.
///
/// `callback_registered` is an operator assertion, not something the
/// coordinator can verify: only the OAuth app's own settings page knows whether
/// `<public_url>/auth/github/callback` is registered. Defaulting it to `false`
/// is what keeps an un-registered deployment on the working device fallback
/// instead of sending every user into a redirect GitHub will refuse.
pub(crate) fn login_method(coord: &Coordinator) -> LoginMethod {
    match coord.config().github.as_ref() {
        None => LoginMethod::None,
        Some(cfg) if cfg.callback_registered => LoginMethod::AuthorizationCode,
        Some(_) => LoginMethod::Device,
    }
}

/// `GET /api/v1/auth/methods`'s body.
#[derive(Debug, Serialize)]
struct AuthMethods {
    login: &'static str,
}

/// The browser-auth routes that are **not** under `/api/v1`.
///
/// `/auth/github/*` is a browser navigation surface, not a JSON API: it answers
/// with redirects and sets cookies, so it lives outside the versioned API
/// prefix that the carrier allowlist keys off.
pub(crate) fn github_router() -> Router<Arc<Coordinator>> {
    Router::new()
        .route("/auth/github/start", get(github_start))
        .route(CALLBACK_PATH, get(github_callback))
}

/// The `/api/v1` routes this module owns, merged by [`crate::api::router`].
pub(crate) fn api_routes() -> Router<Arc<Coordinator>> {
    Router::new()
        .route("/api/v1/auth/methods", get(auth_methods))
        .route("/api/v1/session/device/start", post(device_start))
        .route("/api/v1/session/device/poll", post(device_poll))
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// Read one cookie's value from a `Cookie` header.
///
/// Hand-rolled rather than pulling a cookie crate: this is `split(';')`,
/// `split_once('=')` and a charset check, and the dependency would buy parsing
/// of attributes that only ever travel in the *response* direction.
///
/// A missing or garbage cookie is simply "no credential" — never an error, and
/// never a 500. A caller with a mangled cookie jar must get the same answer as
/// a caller with none, or the shape of the failure is itself an oracle.
pub(crate) fn cookie_value<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty() && v.bytes().all(is_cookie_byte))
}

/// The cookie-value charset we accept.
///
/// RFC 6265's `cookie-octet` minus the characters no value this coordinator
/// issues contains. Restricting it is not decoration: every value read here is
/// fed to a token parser or an HMAC comparison, and a permissive charset would
/// let a caller smuggle a `;` or a quote into either.
fn is_cookie_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' | b':')
}

/// Build one `Set-Cookie` value.
///
/// `Secure` is unconditional; see the module documentation. Please do not make
/// it conditional on the scheme.
///
/// **Invariant: `value` must already be in the [`is_cookie_byte`] charset.**
/// Nothing is escaped here, and a `;` in a cookie value does not escape the
/// header — it *ends the value and starts an attribute*, which is how a value
/// would come to set its own `Path` or clear its own `HttpOnly`. Every value
/// this module writes but one is minted in this process (a `prfs1_` token, a
/// hex HMAC, base64url randomness), so the invariant holds by construction.
/// The exception is `prfs_device`, which carries GitHub's `device_code`
/// verbatim; [`device_start`] checks it before calling this.
fn set_cookie(name: &str, value: &str, max_age: i64, http_only: bool) -> String {
    let mut out = format!("{name}={value}; Secure; SameSite=Lax; Path=/; Max-Age={max_age}");
    if http_only {
        out.push_str("; HttpOnly");
    }
    out
}

/// Build the `Set-Cookie` that erases `name`.
fn clear_cookie(name: &str, http_only: bool) -> String {
    let mut out = format!("{name}=; Secure; SameSite=Lax; Path=/; Max-Age=0");
    if http_only {
        out.push_str("; HttpOnly");
    }
    out
}

/// The pair of `Set-Cookie` values that log a browser in.
///
/// Both carry the same `Max-Age`, derived from the `session` row's `expires`,
/// so the CSRF cookie cannot outlive the credential it is derived from. A
/// negative or zero remaining lifetime would be a session already expired at
/// mint time; it is clamped to zero, which the browser reads as "delete", and
/// the caller gets a cookie that never authenticates rather than one that
/// authenticates forever.
pub(crate) fn session_cookies(coord: &Coordinator, token: &str, expires: i64) -> Vec<String> {
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let max_age = expires.saturating_sub(now).max(0);
    let hash = OpaqueToken::parse(token)
        .map(|t| t.hash().as_str().to_owned())
        .unwrap_or_default();
    vec![
        set_cookie(SESSION_COOKIE, token, max_age, true),
        set_cookie(CSRF_COOKIE, &csrf_token(coord, &hash), max_age, false),
    ]
}

/// The pair of `Set-Cookie` values that log a browser out.
pub(crate) fn cleared_session_cookies() -> Vec<String> {
    vec![
        clear_cookie(SESSION_COOKIE, true),
        clear_cookie(CSRF_COOKIE, false),
    ]
}

/// Attach `Set-Cookie` headers to a response.
fn with_cookies(mut response: Response, cookies: &[String]) -> Response {
    for cookie in cookies {
        if let Ok(value) = axum::http::HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

/// A 302 to `location`, carrying `cookies`.
fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut response =
        (StatusCode::FOUND, [(header::LOCATION, location.to_owned())]).into_response();
    for cookie in cookies {
        if let Ok(value) = axum::http::HeaderValue::from_str(cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/// The CSRF key: `HMAC-SHA256(<signing seed>, "probe-rs-fleet/csrf/v1")`.
///
/// Derived from the seed the coordinator already has rather than from a fresh
/// random, for the reason the module documentation gives. `SimpleHmac` accepts
/// a key of any length, so the 32-byte seed goes in directly.
fn csrf_key(coord: &Coordinator) -> [u8; 32] {
    let SigningKeySource::Seed(seed) = coord.config().signing_key;
    let mut mac = <SimpleHmac<Sha256>>::new_from_slice(&seed)
        .expect("SimpleHmac accepts a key of any length");
    mac.update(CSRF_LABEL);
    mac.finalize().into_bytes().into()
}

/// The CSRF token for a session, given the **hash** of its token.
///
/// Keyed off the hash rather than the token so that nothing derived from the
/// credential itself is handed to JavaScript: the hash is what the database
/// stores, and reversing the HMAC to the token is not a thing this buys anyone
/// even in principle.
pub(crate) fn csrf_token(coord: &Coordinator, session_token_hash: &str) -> String {
    let mut mac = <SimpleHmac<Sha256>>::new_from_slice(&csrf_key(coord))
        .expect("SimpleHmac accepts a key of any length");
    mac.update(session_token_hash.as_bytes());
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    hex_lower(&bytes)
}

/// Whether a mutating, cookie-authenticated request carries the right
/// `X-Fleet-Csrf`.
///
/// The single enforcement point: every mutating handler calls this, and the
/// answer is "yes" for a bearer-authenticated call because that credential is
/// not ambient. Comparison is constant-time — the value is an HMAC over a
/// secret key, and a timing oracle on it is a forgery oracle.
pub(crate) fn csrf_ok(
    coord: &Coordinator,
    headers: &HeaderMap,
    session_token_hash: &str,
    by_cookie: bool,
) -> bool {
    use subtle::ConstantTimeEq as _;

    if !by_cookie {
        return true;
    }
    let Some(offered) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let expected = csrf_token(coord, session_token_hash);
    offered.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// [`csrf_token`], for integration tests.
///
/// Exposed the way [`crate::state::Db::pool_for_test`] is: the integration
/// tests live outside the crate, and a test that recomputed the derivation
/// itself could pass while agreeing with nothing the server does. Deriving it
/// through this function is what makes `tests/browser_auth.rs`'s CSRF
/// assertions mean something.
#[must_use]
pub fn csrf_token_for_test(coord: &Coordinator, session_token_hash: &str) -> String {
    csrf_token(coord, session_token_hash)
}

/// Lowercase hex, as everything else in this tree renders a hash.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A URL-safe random value: 32 bytes, base64url, no padding.
///
/// Used for `state` and the PKCE verifier. Both must survive a round trip
/// through a URL and a cookie, so the alphabet matters as much as the entropy.
fn random_urlsafe() -> String {
    use base64::Engine as _;
    use rand_core::RngCore as _;

    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// GET /api/v1/auth/methods
// ---------------------------------------------------------------------------

/// `GET /api/v1/auth/methods` — which login this deployment offers.
///
/// Unauthenticated, deliberately: the page has to know what to render *before*
/// anyone is logged in. It reveals only which of three flows is configured,
/// which an unauthenticated caller can already learn by watching
/// `/auth/device/start` answer `503 device_flow_unconfigured`.
async fn auth_methods(State(coord): State<Arc<Coordinator>>) -> Response {
    Json(AuthMethods {
        login: login_method(&coord).as_str(),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// The authorization-code flow
// ---------------------------------------------------------------------------

/// The `redirect_uri` for this deployment.
///
/// **From `public_url`, never from the request.** See the module documentation:
/// a `Host`-derived callback behind a reverse proxy is an account takeover.
fn redirect_uri(coord: &Coordinator) -> String {
    format!(
        "{}{CALLBACK_PATH}",
        coord.config().public_url.trim_end_matches('/')
    )
}

/// `GET /auth/github/start` — begin an authorization-code login.
///
/// Unauthenticated by necessity: the caller has no credential yet. The `state`
/// and PKCE verifier go into one short-lived `HttpOnly` cookie; `state` is what
/// actually binds the callback to this browser.
///
/// The request headers are taken and **deliberately unused**. That is the
/// point: the `redirect_uri` this redirect carries comes from `public_url`
/// alone (see [`redirect_uri`]), so `Host` and `X-Forwarded-Host` — which
/// anyone who can reach the proxy may set — must not reach it. Naming the
/// parameter and ignoring it says so where the next reader will look, rather
/// than leaving the absence to be inferred.
async fn github_start(State(coord): State<Arc<Coordinator>>, _headers: HeaderMap) -> Response {
    if login_method(&coord) != LoginMethod::AuthorizationCode {
        // Named, not a 404: a deployment that has not registered the callback
        // is a supported one, and the page must be able to say so and fall back
        // rather than show a dead link. Mirrors `device_flow_unconfigured`.
        warn!("an authorization-code login was attempted but no callback is registered");
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser_login_unconfigured",
        );
    }
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };

    let state = random_urlsafe();
    let verifier = random_urlsafe();
    let challenge = github::pkce_challenge(&verifier);
    let url = github::authorization_url(&app, &redirect_uri(&coord), &state, &challenge);

    // One cookie holding both halves: they are created together, consumed
    // together and expire together, and two cookies would let a browser present
    // a mismatched pair.
    let flow = format!("{state}.{verifier}");
    redirect(
        &url,
        &[set_cookie(OAUTH_COOKIE, &flow, LOGIN_FLOW_TTL_SECS, true)],
    )
}

/// A parsed `?code=…&state=…` query.
///
/// Parsed by hand from [`axum::extract::RawQuery`] rather than with the `Query`
/// extractor: `axum` is pinned `default-features = false` without the `query`
/// feature (see the workspace `Cargo.toml`), and two keys do not justify
/// pulling `serde_urlencoded` + `form_urlencoded` + `serde_path_to_error` into
/// a binary that cross-compiles to armv7-musl.
fn query_pair<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// `GET /auth/github/callback?code&state` — finish an authorization-code login.
///
/// Every failure before the session is minted answers the same way, and none of
/// them mints anything: a mismatched, missing or already-spent `state` is not a
/// condition a caller should be able to tell apart from a mistyped URL.
async fn github_callback(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    if login_method(&coord) != LoginMethod::AuthorizationCode {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser_login_unconfigured",
        );
    }
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };

    let query = query.unwrap_or_default();
    let (Some(code), Some(state)) = (query_pair(&query, "code"), query_pair(&query, "state"))
    else {
        warn!("an authorization-code callback arrived without both `code` and `state`");
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };

    // The `state` cookie is the control. It is `HttpOnly` and `SameSite=Lax`,
    // so a page on another origin can neither read it nor cause it to be sent
    // with a cross-site request it forged; a callback whose `state` does not
    // match it is not this browser's login.
    let Some(flow) = cookie_value(&headers, OAUTH_COOKIE) else {
        warn!("an authorization-code callback arrived with no login cookie");
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some((expected_state, verifier)) = flow.split_once('.') else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        warn!("an authorization-code callback's state did not match its cookie");
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let verifier = verifier.to_owned();

    // Cleared before anything else can fail, so a `state` is single-use: a
    // replayed callback finds no cookie and is refused by the branch above.
    let spent = clear_cookie(OAUTH_COOKIE, true);

    let access_token =
        match github::exchange_code(&app, code, &redirect_uri(&coord), &verifier).await {
            Ok(token) => token,
            Err(e) => {
                warn!(error = %e, "the GitHub authorization-code exchange failed");
                return with_cookies(reject(StatusCode::UNAUTHORIZED, "invalid_grant"), &[spent]);
            }
        };

    match complete_github_login(&coord, &app, &access_token, "github authorization code").await {
        Ok(cookies) => {
            let mut all = vec![spent];
            all.extend(cookies);
            redirect("/ui", &all)
        }
        Err(response) => with_cookies(response, &[spent]),
    }
}

/// Resolve a GitHub access token to a fleet session, and produce its cookies.
///
/// Shared by both browser logins, so the identity provisioning cannot drift
/// between them. The GitHub access token is spent here and discarded: one
/// `GET /user`, and only a fleet session token survives the call.
#[allow(clippy::result_large_err)]
async fn complete_github_login(
    coord: &Coordinator,
    app: &github::GithubApp,
    access_token: &str,
    audit_detail: &str,
) -> Result<Vec<String>, Response> {
    let user = match github::fetch_user(app, access_token).await {
        Ok(user) => user,
        Err(e) => {
            warn!(error = %e, "could not read the GitHub user behind a browser login");
            return Err(reject(StatusCode::BAD_GATEWAY, "upstream_error"));
        }
    };
    // The immutable numeric id is the identity; `login` is cached for display.
    // Keying off the login would let a rename + re-claim land the new owner in
    // the old owner's org (see `Db::upsert_github_user`).
    let Ok(gh_id) = i64::try_from(user.id) else {
        return Err(reject(StatusCode::BAD_GATEWAY, "upstream_error"));
    };
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let (user_id, org, created) = match coord
        .db()
        .upsert_github_user(gh_id, &user.login, user.email.as_deref(), now)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "failed to provision the GitHub user");
            return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
        }
    };
    if created {
        let _ = coord
            .db()
            .scoped(org.clone())
            .append_audit(&AuditEntry {
                ts: now,
                subject: Some(user_id.as_str()),
                action: "user.create",
                node: None,
                board: None,
                lease: None,
                detail: Some("browser login: personal org created"),
            })
            .await;
        info!(user = %user_id, org = %org, "provisioned a user and its personal org");
    }

    let ttl = coord.config().session_ttl_secs;
    let (token, expires) =
        match mint_session_for_user(coord, &org, &user_id, ttl, audit_detail).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to mint a session token after a browser login");
                return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
            }
        };
    Ok(session_cookies(coord, &token, expires))
}

/// Constant-time byte comparison, for values an attacker chooses one side of.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// The cookie-brokered device fallback
// ---------------------------------------------------------------------------

/// `POST /api/v1/session/device/start`'s body. **No `device_code`.**
#[derive(Debug, Serialize)]
struct BrokeredDeviceStart {
    user_code: String,
    verification_uri: String,
    interval: u64,
    expires_in: u64,
}

/// `POST /api/v1/session/device/poll`'s body. **Never a token.**
#[derive(Debug, Serialize)]
struct BrokeredDevicePoll {
    status: &'static str,
}

/// `POST /api/v1/session/device/start` — the browser sibling of
/// [`crate::http::auth_device_start`].
///
/// Identical brokering, with the `device_code` moved out of the response body
/// and into an `HttpOnly` cookie. That relocation is the entire reason this
/// route exists rather than the page calling `/auth/device/start`.
async fn device_start(State(coord): State<Arc<Coordinator>>) -> Response {
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };
    match github::start_device_flow(&app).await {
        Ok(grant) => {
            // The one cookie value this module does not mint itself. A `;` in
            // it would not escape the header — it would end the value and
            // start an *attribute*, which is how an upstream string could come
            // to set its own `Path` or clear its own `HttpOnly`. GitHub's
            // device codes are already in this charset, so refusing is the
            // conservative direction: a code outside it means GitHub changed
            // its wire format, and the operator should hear that as a failed
            // login rather than as a cookie behaving strangely.
            if grant.device_code.is_empty() || !grant.device_code.bytes().all(is_cookie_byte) {
                warn!(
                    "GitHub returned a device code outside the cookie token charset; \
                     refusing to broker it"
                );
                return reject(StatusCode::BAD_GATEWAY, "upstream_error");
            }
            let ttl = i64::try_from(grant.expires_in).unwrap_or(LOGIN_FLOW_TTL_SECS);
            let body = Json(BrokeredDeviceStart {
                user_code: grant.user_code,
                verification_uri: grant.verification_uri,
                interval: grant.interval,
                expires_in: grant.expires_in,
            })
            .into_response();
            with_cookies(
                body,
                &[set_cookie(DEVICE_COOKIE, &grant.device_code, ttl, true)],
            )
        }
        Err(e) => {
            warn!(error = %e, "failed to start a brokered GitHub device flow");
            reject(StatusCode::BAD_GATEWAY, "upstream_error")
        }
    }
}

/// `POST /api/v1/session/device/poll` — the browser sibling of
/// [`crate::http::auth_device_poll`].
///
/// Answers `{"status":"pending"}` or `{"status":"ok"}` and nothing else. On
/// `ok` the session arrives as cookies; the token never appears in a body.
///
/// The poll states GitHub distinguishes (`slow_down`, `expired_token`,
/// `access_denied`) collapse to `pending` / a flat rejection here, unlike on
/// `/auth/device/poll` where the CLI needs them to drive its own loop: a page
/// polling its own in-flight login has one useful branch, and the coordinator's
/// log keeps the detail.
async fn device_poll(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };
    let Some(device_code) = cookie_value(&headers, DEVICE_COOKIE) else {
        // No cookie is not "pending": there is no flow to poll, and answering
        // `pending` would leave the page looping forever.
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };

    let access_token = match github::poll_device_flow(&app, device_code).await {
        Ok(DevicePoll::Granted { access_token }) => access_token,
        Ok(DevicePoll::Pending | DevicePoll::SlowDown { .. }) => {
            return Json(BrokeredDevicePoll { status: "pending" }).into_response();
        }
        Ok(DevicePoll::Expired | DevicePoll::Denied) => {
            return with_cookies(
                reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
                &[clear_cookie(DEVICE_COOKIE, true)],
            );
        }
        Err(e) => {
            warn!(error = %e, "brokered GitHub device-flow poll failed");
            return with_cookies(
                reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
                &[clear_cookie(DEVICE_COOKIE, true)],
            );
        }
    };

    match complete_github_login(&coord, &app, &access_token, "github device flow (browser)").await {
        Ok(mut cookies) => {
            cookies.push(clear_cookie(DEVICE_COOKIE, true));
            with_cookies(
                Json(BrokeredDevicePoll { status: "ok" }).into_response(),
                &cookies,
            )
        }
        Err(response) => with_cookies(response, &[clear_cookie(DEVICE_COOKIE, true)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        h
    }

    #[test]
    fn cookie_parsing_finds_a_value_among_others() {
        let h = headers_with("other=1; prfs_session=prfs1_abc; prfs_csrf=deadbeef");
        assert_eq!(cookie_value(&h, SESSION_COOKIE), Some("prfs1_abc"));
        assert_eq!(cookie_value(&h, CSRF_COOKIE), Some("deadbeef"));
        assert_eq!(cookie_value(&h, "absent"), None);
    }

    /// A mangled cookie jar is "no credential", not a 500 and not a partial
    /// parse: whatever the browser sent, the answer must be the one an absent
    /// cookie produces.
    #[test]
    fn garbage_cookies_are_simply_absent() {
        for raw in [
            "prfs_session",
            "prfs_session=",
            "prfs_session=has space",
            "prfs_session=quote\"d",
            "=novalue",
            ";;;",
        ] {
            let h = headers_with(raw);
            assert_eq!(cookie_value(&h, SESSION_COOKIE), None, "{raw}");
        }
    }

    #[test]
    fn set_cookie_is_always_secure_and_lax() {
        let c = set_cookie(SESSION_COOKIE, "prfs1_x", 42, true);
        assert!(c.contains("Secure"), "{c}");
        assert!(c.contains("SameSite=Lax"), "{c}");
        assert!(c.contains("Path=/"), "{c}");
        assert!(c.contains("Max-Age=42"), "{c}");
        assert!(c.contains("HttpOnly"), "{c}");
        // The CSRF cookie is the one the page must read.
        let c = set_cookie(CSRF_COOKIE, "abc", 42, false);
        assert!(!c.contains("HttpOnly"), "{c}");
        assert!(c.contains("Secure"), "{c}");
    }

    /// `set_cookie` escapes nothing, so the values it is handed must already be
    /// in the charset. Every value this module mints satisfies that by
    /// construction; this pins the charset predicate itself, which is what
    /// [`device_start`] screens GitHub's `device_code` with. A `;` is the one
    /// that matters: in a cookie value it ends the value and begins an
    /// *attribute*.
    #[test]
    fn the_cookie_charset_rejects_attribute_injection() {
        for bad in ["a;Path=/evil", "a b", "a\"b", "a,b", "a\\b"] {
            assert!(
                !bad.bytes().all(is_cookie_byte),
                "{bad} must not pass the cookie charset"
            );
        }
        // The shapes we actually emit, and GitHub's device codes, do pass.
        for good in [
            "prfs1_bTVhY2hpbmU",
            "deadbeef00",
            "dc-abc123",
            "3584d83530557fdd1f46af8289938c8ef79f9dc5",
            "c0FSTUpBRlJ",
        ] {
            assert!(good.bytes().all(is_cookie_byte), "{good} must pass");
        }
    }

    #[test]
    fn query_pairs_are_extracted_by_key() {
        assert_eq!(query_pair("code=abc&state=xyz", "code"), Some("abc"));
        assert_eq!(query_pair("code=abc&state=xyz", "state"), Some("xyz"));
        assert_eq!(query_pair("code=abc", "state"), None);
        assert_eq!(query_pair("", "code"), None);
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
