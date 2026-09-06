//! The browser-facing JSON API at `/api/v1` (`docs/web-ui.md` D2).
//!
//! One `Router`, every JSON handler, and the view structs that shape the
//! responses. Phase 1a is **read-only** apart from `POST /api/v1/session/logout`
//! — see [§ Why one mutating route](#why-one-mutating-route).
//!
//! # The no-drift guarantee is structural
//!
//! Every endpoint that has a wire counterpart calls the *same*
//! [`Coordinator`] core method `handle_sidecar_message` dispatches to
//! ([`Coordinator::list_boards_core`], [`Coordinator::who_core`],
//! [`Coordinator::logs_core`]), and those cores hold the authorization checks.
//! HTTP is a second **encoding**, not a second authorization implementation.
//!
//! > A handler that re-implements a check, or reaches for
//! > [`crate::state::OrgDb`] directly instead of calling a core, is the exact
//! > failure mode this design exists to prevent. If a check is tempting to
//! > write "just this once", it has to move into a `Coordinator` method that
//! > both surfaces call.
//!
//! # Errors are coarse, and there is no existence oracle
//!
//! Bodies are the existing `{"error":"<code>"}` shape, produced by the same
//! [`crate::http::reject`] every other route uses. A cross-org object and a
//! nonexistent one must be **indistinguishable**: both arrive here as
//! [`OpError::Denied`] or [`OpError::NotFound`] out of the org-blind
//! `Access` / `require_lease_control` paths, and [`op_error`] does not refine
//! them per endpoint. The REST instinct to answer `404` for "no such node" and
//! `403` for "not yours" is explicitly wrong here (`docs/web-ui.md` §4): it
//! turns the API into an org-enumeration oracle.
//!
//! # No capability token ever reaches the browser
//!
//! Not `LeaseGrant::token`, not `ChannelOpened::token`, not the `/delegate`
//! bearer. A capability token is offline-verifiable and cannot be revoked short
//! of tearing down the lease, which makes it exactly the wrong thing to put
//! where an XSS can read it. The view structs below are the enforcement: they
//! name the fields they expose rather than deriving `Serialize` on a wire type
//! that might grow one, and `tests/api_readonly.rs` asserts no response body
//! contains a token prefix.
//!
//! # Why one mutating route
//!
//! `docs/web-ui.md` §6's phase fence says phase 1 ships "no mutating endpoint
//! at all, so the cookie, CSP and CSRF machinery ship and get exercised before
//! anything exists that could be abused through them". `POST
//! /api/v1/session/logout` is the deliberate exception: it destroys only the
//! caller's own credential, and shipping the CSRF check with exactly one
//! consumer is how that machinery gets exercised at all. Please do not add a
//! second mutating route here "while you are in there" — the fence is the
//! reason the CSRF code can be trusted before there is anything worth
//! attacking.
//!
//! # Query strings
//!
//! `axum` is pinned `default-features = false` without the `query` feature
//! (workspace `Cargo.toml`), so the `Query` extractor does not exist. The one
//! endpoint that needs a parameter — `GET /api/v1/audit?board=…` — uses the
//! always-available [`axum::extract::RawQuery`] and [`query_value`] below.
//! **Recorded decision:** `RawQuery` over enabling the feature, because two
//! call sites do not justify pulling `serde_urlencoded` + `form_urlencoded` +
//! `serde_path_to_error` into a binary that cross-compiles to armv7-musl
//! (`docs/cross-compiling.md`), and the parser is twenty lines with its own
//! unit tests.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tracing::warn;

use fleet_auth::TokenKind;
use fleet_proto::admin::{BoardAvailability, BoardSummary, LeaseHolderSummary, LogLine};
use fleet_proto::board::PowerKind;
use fleet_proto::ids::{BoardName, BoardRef, Role, Subject, SubjectKey};

use crate::browser_auth::{cleared_session_cookies, csrf_ok};
use crate::core::{Coordinator, NodeStatus, OpError};
use crate::http::{authenticate_request_with, reject, Arrival, Carrier};

/// Build the `/api/v1` router, merged into the coordinator's by
/// [`crate::http::router`].
///
/// The paths are written in full rather than nested, so `grep '/api/v1'` finds
/// every one of them: this is the exact surface on which a **cookie** is an
/// accepted credential, and that allowlist is the blast-radius fence
/// (`docs/web-ui.md` D1).
pub(crate) fn router() -> Router<Arc<Coordinator>> {
    Router::new()
        .route("/api/v1/session", get(session))
        .route("/api/v1/session/logout", post(logout))
        .route("/api/v1/org", get(org))
        .route("/api/v1/org/members", get(org_members))
        .route("/api/v1/nodes", get(nodes))
        .route("/api/v1/boards", get(boards))
        .route("/api/v1/leases", get(leases))
        .route("/api/v1/audit", get(audit))
        .merge(crate::browser_auth::api_routes())
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Authenticate an `/api/v1` request, accepting the session cookie.
///
/// The one place this surface builds a caller from wire input, and it does so
/// by delegating to [`authenticate_request_with`] — still the only `Subject`
/// construction site in the coordinator. `TokenKind::Session` only: a node or
/// workload token has no business on the browser API, and saying so explicitly
/// beats relying on the absence of a membership row.
async fn api_auth(
    coord: &Coordinator,
    headers: &HeaderMap,
) -> Result<(fleet_auth::Authenticated, Subject, Arrival), Response> {
    authenticate_request_with(
        coord,
        headers,
        &[TokenKind::Session],
        Carrier::HeaderOrCookie,
    )
    .await
}

/// Turn an [`OpError`] into the uniform JSON rejection.
///
/// The messages the cores carry are for the **wire** surface, whose callers are
/// CLIs that render them; they are deliberately dropped here. A JSON API that
/// echoed "no such board nrf52840-dk-3" would answer a question about another
/// org's inventory in the one case where the caller guessed right.
fn op_error(e: &OpError) -> Response {
    match e {
        OpError::Denied => reject(StatusCode::FORBIDDEN, "forbidden"),
        OpError::NotFound(_) => reject(StatusCode::NOT_FOUND, "not_found"),
        OpError::Invalid(_) => reject(StatusCode::BAD_REQUEST, "invalid_request"),
        OpError::Conflict(_) => reject(StatusCode::CONFLICT, "conflict"),
        OpError::Internal(err) => {
            warn!(error = %err, "an /api/v1 handler failed");
            reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// Look up one key in a raw query string, percent-decoding its value.
///
/// See the module documentation for why this exists rather than
/// `axum::extract::Query`. Repeated keys resolve to the **first**, which is the
/// conservative reading: a request carrying `?board=a&board=b` is malformed,
/// and picking the last would let a proxy-injected trailer win over what the
/// caller wrote.
pub(crate) fn query_value(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| percent_decode(k) == key)
        .map(|(_, v)| percent_decode(v))
}

/// Decode `%xx` escapes and `+` in one query-string component.
///
/// **Operates on bytes, never on `&str` slices.** A percent-decoder that
/// indexed the `&str` (`&s[i + 1..i + 3]`) would panic on a `%` immediately
/// before a multi-byte character, and that is reachable input: `http`'s query
/// scanner accepts any `0x80..=0xFF` byte, so `?board=%€x` arrives here intact
/// and would take down the handler — before any authorization check, since
/// this runs on the way to [`Coordinator::logs_core`] rather than after it.
/// Decoding byte-wise and letting [`String::from_utf8_lossy`] repair the
/// result at the end keeps every input a value rather than a crash.
fn percent_decode(s: &str) -> String {
    /// One hex digit, or `None`.
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // `i + 2 < len` is the right bound: `%41` at the very end has its
            // last digit at `len - 1`, so it still decodes.
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push(hi * 16 + lo);
                    i += 3;
                    continue;
                }
                // Not an escape after all — a literal `%`, which is malformed
                // but not worth refusing a whole request over.
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// View structs
// ---------------------------------------------------------------------------
//
// These live here, never in `fleet-proto`. The wire DTOs are shaped for
// postcard — newtype ids, a three-part `BoardRef`, externally-tagged enums —
// and serializing them straight to JSON produces shapes like
// `{"Uhubctl":{"hub":"1-1","port":2}}` that a hand-written frontend would have
// to special-case. Giving `fleet-proto` a divergent field set to fix that would
// mean the browser and the CLI disagreed about what a board *is*, which is
// precisely the drift `docs/web-ui.md` D2 exists to prevent.

/// A board key, both structured and flattened.
///
/// A `BoardRef` is four slash-separated segments (`org/org/node/name`, since a
/// node id is itself `{org}/{name}`), so boards are never addressed in a URL
/// path. `key` is the flattened rendering — the same string `BoardRef`'s
/// `Display` produces — so the frontend has one opaque value to put in a body
/// field and to use as a list key, while `node` / `name` stay available for
/// display without string surgery.
#[derive(Debug, Serialize)]
struct BoardKeyView {
    key: String,
    org: String,
    node: String,
    name: String,
}

impl From<&BoardRef> for BoardKeyView {
    fn from(board: &BoardRef) -> Self {
        Self {
            key: board.to_string(),
            org: board.org.0.clone(),
            node: board.node.0.clone(),
            name: board.name.clone(),
        }
    }
}

/// A subject, flattened the way the audit log renders one.
#[derive(Debug, Serialize)]
struct SubjectView {
    key: String,
    org: String,
    kind: String,
    id: String,
}

impl From<&Subject> for SubjectView {
    fn from(subject: &Subject) -> Self {
        Self::from(&subject.key())
    }
}

impl From<&SubjectKey> for SubjectView {
    fn from(key: &SubjectKey) -> Self {
        Self {
            key: key.to_string(),
            org: key.org.0.clone(),
            kind: key.kind.to_string(),
            id: key.id.clone(),
        }
    }
}

/// One row of `GET /api/v1/boards`.
#[derive(Debug, Serialize)]
struct BoardView {
    board: BoardKeyView,
    node: String,
    chip: String,
    tags: Vec<String>,
    exclusive: bool,
    /// `uhubctl` / `gpio` / `none`. The wiring detail (hub, port, gpio line) is
    /// deliberately **not** exposed: the browser has no use for it and it
    /// describes the physical layout of somebody's lab.
    power: &'static str,
    /// `available` / `leased` / `faulted` / `disabled`.
    availability: &'static str,
    holder: Option<SubjectView>,
    lease: Option<u64>,
    expires: Option<u64>,
}

impl From<BoardSummary> for BoardView {
    fn from(b: BoardSummary) -> Self {
        Self {
            board: BoardKeyView::from(&b.board),
            node: b.agent.0,
            chip: b.chip,
            tags: b.tags,
            exclusive: b.exclusive,
            power: match b.power {
                PowerKind::Uhubctl { .. } => "uhubctl",
                PowerKind::Gpio { .. } => "gpio",
                PowerKind::None => "none",
            },
            availability: match b.availability {
                BoardAvailability::Available => "available",
                BoardAvailability::Leased => "leased",
                BoardAvailability::Faulted => "faulted",
                BoardAvailability::Disabled => "disabled",
            },
            holder: b.holder.as_ref().map(SubjectView::from),
            lease: b.lease.map(|l| l.0),
            expires: b.expires,
        }
    }
}

/// One row of `GET /api/v1/leases`.
#[derive(Debug, Serialize)]
struct LeaseView {
    lease: u64,
    board: BoardKeyView,
    holder: SubjectView,
    expires: u64,
}

impl From<LeaseHolderSummary> for LeaseView {
    fn from(l: LeaseHolderSummary) -> Self {
        Self {
            lease: l.lease.0,
            board: BoardKeyView::from(&l.board),
            holder: SubjectView::from(&l.holder),
            expires: l.expires,
        }
    }
}

/// One row of `GET /api/v1/audit`.
///
/// [`LogLine`] happens to serialize to pleasant JSON already, but it is
/// re-shaped here anyway so that a future field added for the CLI's benefit
/// does not silently appear in a browser response.
#[derive(Debug, Serialize)]
struct LogLineView {
    ts: i64,
    action: String,
    board: Option<String>,
    detail: Option<String>,
}

impl From<LogLine> for LogLineView {
    fn from(l: LogLine) -> Self {
        Self {
            ts: l.ts,
            action: l.action,
            board: l.board,
            detail: l.detail,
        }
    }
}

/// One row of `GET /api/v1/nodes`.
#[derive(Debug, Serialize)]
struct NodeView {
    id: String,
    name: String,
    tags: Vec<String>,
    /// `auto` / `declared`: whether undeclared probes on this machine are
    /// adopted.
    adopt: &'static str,
    /// The owning user id, or `null` for a node enrolled with an auth key,
    /// which has no owning human by construction.
    owner: Option<String>,
    last_seen: Option<i64>,
    created_at: i64,
    /// Whether the node currently holds its control-plane `WebSocket`. Read
    /// from the live registry, not from a column: a database flag would be
    /// stale from the moment a process died.
    online: bool,
    /// Node-local board names.
    boards: Vec<String>,
}

impl From<NodeStatus> for NodeView {
    fn from(n: NodeStatus) -> Self {
        Self {
            id: n.row.id.0,
            name: n.row.name,
            tags: n.row.tags,
            adopt: n.row.adopt.as_str(),
            owner: n.row.owner_user_id,
            last_seen: n.row.last_seen,
            created_at: n.row.created_at,
            online: n.online,
            boards: n.row.boards,
        }
    }
}

/// `GET /api/v1/session`'s body.
#[derive(Debug, Serialize)]
struct SessionView {
    user: String,
    /// The cached GitHub login, for display. `None` for a user created by the
    /// interim `coordinator user-token` verb.
    login: Option<String>,
    org: String,
    org_slug: Option<String>,
    role: &'static str,
    /// The session row's expiry. The UI needs it to bounce to a fresh login
    /// *before* the next call 401s; there is no silent refresh in v1
    /// (`docs/web-ui.md` D1).
    expires: Option<u64>,
}

/// `GET /api/v1/org`'s body.
#[derive(Debug, Serialize)]
struct OrgView {
    id: String,
    slug: Option<String>,
    /// `personal` | `team` | `system`, read from the `org` row's own column.
    ///
    /// Read rather than assumed: every production creation path writes
    /// `personal` today, so a constant would be *currently* correct — and
    /// silently wrong the first time a team org exists, in a field whose name
    /// promises it reports the column.
    kind: Option<String>,
    role: &'static str,
}

/// One row of `GET /api/v1/org/members`.
#[derive(Debug, Serialize)]
struct MemberView {
    user_id: String,
    login: Option<String>,
    role: &'static str,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/session` — who the caller is.
///
/// The first call any page makes. Membership is not required: a session whose
/// membership was revoked must still be able to learn that it has none, or the
/// UI has no way to render anything but a blank 403.
async fn session(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let role = match coord.db().role_of(&subject.org, &auth.id).await {
        Ok(role) => role,
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let login = match coord.db().user_login(&auth.id).await {
        Ok(login) => login,
        Err(e) => {
            warn!(error = %e, "failed to resolve a login for display");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let org_slug = match coord.db().org_slug(&subject.org).await {
        Ok(slug) => slug,
        Err(e) => {
            warn!(error = %e, "failed to resolve an org slug");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    Json(SessionView {
        user: auth.id.clone(),
        login,
        org: subject.org.0.clone(),
        org_slug,
        role: role.map_or("none", Role::as_str),
        expires: auth.expires,
    })
    .into_response()
}

/// `POST /api/v1/session/logout` — destroy the caller's own session.
///
/// The one mutating route in phase 1a, and the one consumer of the CSRF check;
/// see the module documentation. It deletes exactly the row the caller
/// authenticated with — never one named in the request — so the worst a
/// successful forgery could achieve is logging somebody out.
///
/// `204` with both cookies cleared, whether or not the row was there: a
/// caller must not be able to distinguish "logged out" from "already gone".
async fn logout(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (auth, _subject, arrival) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    if !csrf_ok(
        &coord,
        &headers,
        auth.hash.as_str(),
        arrival == Arrival::Cookie,
    ) {
        warn!(subject = %auth.id, "a cookie-authenticated mutating call had no valid CSRF header");
        return reject(StatusCode::FORBIDDEN, "forbidden");
    }
    if let Err(e) = coord.db().delete_session(auth.hash.as_str()).await {
        warn!(error = %e, "failed to delete a session on logout");
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    for cookie in cleared_session_cookies() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

/// `GET /api/v1/org` — the caller's org.
///
/// Member-gated: an authenticated non-member learns nothing about the org its
/// session names, which is the same answer `require_role` gives everywhere
/// else.
async fn org(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let org = subject.org.clone();
    let Ok(()) = crate::authz::require_role(coord.db(), &subject, &org, Role::Member).await else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let role = match coord.db().role_of(&org, &subject.id).await {
        Ok(Some(role)) => role,
        Ok(None) => return reject(StatusCode::FORBIDDEN, "forbidden"),
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let (slug, kind) = match coord.db().org_slug_and_kind(&org).await {
        // An org a live session names but no `org` row backs is not a
        // condition to paper over with defaults; it cannot happen (`session`
        // carries a foreign key onto `org`), and if it ever does the honest
        // answer is nulls rather than an invented `personal`.
        Ok(Some((slug, kind))) => (Some(slug), Some(kind)),
        Ok(None) => (None, None),
        Err(e) => {
            warn!(error = %e, "failed to resolve an org slug");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    Json(OrgView {
        id: org.0.clone(),
        slug,
        kind,
        role: role.as_str(),
    })
    .into_response()
}

/// `GET /api/v1/org/members` — the org's membership, read-only in v1.
async fn org_members(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_members_core(&subject).await {
        Ok(members) => Json(
            members
                .into_iter()
                .map(|m| MemberView {
                    user_id: m.user_id,
                    login: m.login,
                    role: m.role.as_str(),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/nodes` — the org's machines.
///
/// New surface: there is no wire verb for it, because `ctl list` is
/// board-shaped and a machine that has plugged in no probes is invisible to it.
async fn nodes(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_nodes_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(NodeView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/boards` — the same inventory `ctl list` renders.
async fn boards(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_boards_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(BoardView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/leases` — the same table `ctl who` renders.
async fn leases(State(coord): State<Arc<Coordinator>>, headers: HeaderMap) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.who_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(LeaseView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/audit?board=<name>` — the org's audit log, admin-only.
///
/// **No paging and no filtering beyond `board`** in v1: `logs_core` reads
/// `OrgDb::recent_audit` with a hardcoded limit of 200 and this endpoint keeps
/// that number rather than inventing a cursor API for one surface. Stated here
/// so the first reader does not see "audit log" and expect one.
async fn audit(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let (_auth, subject, _) = match api_auth(&coord, &headers).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let board = query
        .as_deref()
        .and_then(|q| query_value(q, "board"))
        .filter(|b| !b.is_empty())
        .map(BoardName);
    match coord.logs_core(&subject, board.as_ref()).await {
        Ok(lines) => {
            Json(lines.into_iter().map(LogLineView::from).collect::<Vec<_>>()).into_response()
        }
        Err(e) => op_error(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_are_found_and_decoded() {
        assert_eq!(
            query_value("board=nrf52840-dk-3", "board").as_deref(),
            Some("nrf52840-dk-3")
        );
        assert_eq!(
            query_value("a=1&board=rpi-1%2Fdk-3&b=2", "board").as_deref(),
            Some("rpi-1/dk-3")
        );
        assert_eq!(query_value("board=a+b", "board").as_deref(), Some("a b"));
        assert_eq!(query_value("a=1", "board"), None);
        assert_eq!(query_value("", "board"), None);
        // A repeated key resolves to the first, never the last.
        assert_eq!(query_value("board=a&board=b", "board").as_deref(), Some("a"));
    }

    /// A percent-decoder that sliced the `&str` by byte index would panic here,
    /// on input any authenticated session can send and *before* the endpoint's
    /// admin check runs. Pinned rather than left to be re-derived.
    #[test]
    fn a_malformed_escape_decodes_rather_than_panicking() {
        // `%` immediately before a multi-byte character: bytes `i+1`/`i+2` land
        // inside it, which is the char-boundary panic.
        assert_eq!(query_value("board=%\u{20ac}x", "board").as_deref(), Some("%\u{20ac}x"));
        // The same shape in the *key*, which is decoded for every pair.
        assert_eq!(query_value("%\u{20ac}x=1&board=ok", "board").as_deref(), Some("ok"));
        // Stray `%`s, truncated escapes and non-hex digits are literals.
        assert_eq!(query_value("board=%", "board").as_deref(), Some("%"));
        assert_eq!(query_value("board=%4", "board").as_deref(), Some("%4"));
        assert_eq!(query_value("board=%zz", "board").as_deref(), Some("%zz"));
        assert_eq!(query_value("board=a%", "board").as_deref(), Some("a%"));
        // A complete escape at the very end still decodes: the bound is
        // `i + 2 < len`, and `%41`'s last digit sits at `len - 1`.
        assert_eq!(query_value("board=dk%41", "board").as_deref(), Some("dkA"));
        // A percent-escaped byte sequence that is not valid UTF-8 is repaired,
        // not rejected: this is a board name that will match nothing, which is
        // the right outcome for a lookup.
        assert_eq!(query_value("board=%ff", "board").as_deref(), Some("\u{fffd}"));
    }

    /// A `BoardRef` is four segments, so the flattened key is what a body field
    /// carries; the parts stay available for display.
    #[test]
    fn a_board_key_carries_both_shapes() {
        let board = BoardRef::new(
            fleet_proto::ids::OrgId("gh-1".to_owned()),
            fleet_proto::ids::AgentId("gh-1/rpi-1".to_owned()),
            "dk-3",
        );
        let view = BoardKeyView::from(&board);
        assert_eq!(view.key, "gh-1/gh-1/rpi-1/dk-3");
        assert_eq!(view.org, "gh-1");
        assert_eq!(view.node, "gh-1/rpi-1");
        assert_eq!(view.name, "dk-3");
    }

    /// The power wiring is a fact about somebody's lab bench, not about the
    /// board's availability, and the browser has no use for it.
    #[test]
    fn power_kinds_flatten_to_labels_without_the_wiring() {
        let json = serde_json::to_string(&BoardView::from(BoardSummary {
            board: BoardRef::new(
                fleet_proto::ids::OrgId("o".to_owned()),
                fleet_proto::ids::AgentId("o/n".to_owned()),
                "b",
            ),
            agent: fleet_proto::ids::AgentId("o/n".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec![],
            exclusive: true,
            power: PowerKind::Uhubctl {
                hub: "1-1".to_owned(),
                port: 2,
            },
            availability: BoardAvailability::Available,
            holder: None,
            lease: None,
            expires: None,
        }))
        .unwrap();
        assert!(json.contains(r#""power":"uhubctl""#), "{json}");
        assert!(!json.contains("1-1"), "{json}");
        assert!(json.contains(r#""availability":"available""#), "{json}");
    }
}
