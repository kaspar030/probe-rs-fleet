//! The browser-facing JSON API at `/api/v1` (`docs/web-ui.md` D2).
//!
//! One `Router`, every JSON handler, and the view structs that shape the
//! responses. Phase 1a was read-only apart from `POST /api/v1/session/logout`;
//! phase 1b adds the node-management verbs and phase 1c the outward-pointing
//! ones — see
//! [§ Which routes mutate, and why](#which-routes-mutate-and-why).
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
//! Not `LeaseGrant::token`, not `ChannelOpened::token`, not
//! `ChannelOpened::serve_token`, not the `/delegate` bearer. A capability token
//! is offline-verifiable and cannot be revoked short of tearing down the lease,
//! which makes it exactly the wrong thing to put where an XSS can read it; the
//! serve token is a live loopback credential for a leased board and belongs
//! there just as little. The view structs below are the enforcement: they
//! name the fields they expose rather than deriving `Serialize` on a wire type
//! that might grow one, and `tests/api_readonly.rs` asserts no response body
//! contains a token prefix.
//!
//! `POST /api/v1/auth-keys` is the one deliberate exception and it is **not** a
//! counter-example: an auth key is a revocable, org-scoped, expiring
//! *enrollment* credential, not an offline-verifiable capability over a leased
//! board. `docs/web-ui.md` D4 accepts the cost explicitly, because the
//! alternative is a UI whose most-asked-for enrollment path is the one thing
//! you must leave the browser for. See [`create_auth_key`].
//!
//! # Which routes mutate, and why
//!
//! `docs/web-ui.md` §6's phase fence put phase 1a's cookie, CSP and CSRF
//! machinery in front of anything worth abusing: `POST /api/v1/session/logout`
//! was its single, self-directed consumer. Phase **1b** is the first set of
//! genuinely mutating endpoints, and the fence is what lets them be trusted:
//!
//! * `PATCH /api/v1/nodes/{name}` — tags and adoption policy. **Not the name**;
//!   see [`update_node`].
//! * `DELETE /api/v1/nodes/{name}` — a revocation, cascading through the live
//!   leases, the scheduler and the node's connection; see [`delete_node`].
//! * `POST /api/v1/nodes/pending/{code}` — inspect / approve / deny a pending
//!   node registration, cashing in `docs/architecture.md` §4.2's promise that a
//!   cookie-authenticated handler would call the *same*
//!   [`crate::http::decide_pending_node`]; see [`decide_pending`].
//!
//! Phase **1c** adds the outward-pointing verbs — the two surfaces where a
//! mistake hands hardware to somebody else, which is why the doc's phase fence
//! put them last:
//!
//! * `POST /api/v1/grants` / `DELETE /api/v1/grants/{id_prefix}` — sharing this
//!   org's hardware with a subject who is not in it, and taking it back. Create
//!   is **admin**-gated while list is member-gated; that divergence is
//!   deliberate and lives in the cores. See [`create_grant`].
//! * `POST /api/v1/auth-keys` / `DELETE /api/v1/auth-keys/{hash_prefix}` —
//!   minting and revoking enrollment credentials, by **calling**
//!   [`forgs_http::keys::create`] / [`forgs_http::keys::revoke`] — the same
//!   functions forgs' `/auth/keys` uses. See [`create_auth_key`].
//! * `POST /api/v1/boards/power-cycle` — the one [`fleet_proto::token::AllowedOp`]
//!   the *coordinator* enforces; see [`power_cycle`].
//! * `DELETE /api/v1/leases/{lease_id}` — holder-or-admin lease release,
//!   including a board org's admin reclaiming their own hardware from someone
//!   they shared it with; see [`release_lease`].
//!
//! There is deliberately **no** `POST /api/v1/leases` and no `/delegate`
//! equivalent (`docs/web-ui.md` D4): a lease taken in a browser has no sidecar
//! to use it, and delegation hands out a capability token.
//!
//! Every one of them calls [`mutating_auth`] (forgs' `require_csrf`) before touching anything, and the check
//! is a single shared helper rather than a per-handler line of code precisely
//! so that "did this handler remember?" is answerable by grep.
//!
//! There is deliberately **no** `GET /api/v1/nodes/pending`. The doc's original
//! table had one; it is dropped, and `docs/web-ui.md` §3/§4 are amended to say
//! so. `pending_node.org_id` is `NULL` until an approval binds it, so there is
//! no attribution to filter a listing on, and a member-visible list of live
//! codes would be exactly the cross-tenant index §4 forbids — strictly
//! worsening the enumeration risk §6.4 accepts. Approval stays code-driven.
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

use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use forgs::TokenKind;
use forgs_http::{Caller, Carrier};

use fleet_proto::admin::{
    BoardAvailability, BoardSummary, GrantSummary, LeaseHolderSummary, LogLine,
};
use fleet_proto::adopt::AdoptPolicy;
use fleet_proto::auth_api::NodeApprovalDecision;
use fleet_proto::board::PowerKind;
use fleet_proto::ids::{BoardName, BoardRef, LeaseId, SubjectKey};
use fleet_proto::token::AllowedOp;

use crate::core::{Coordinator, NodeStatus, OpError};
use crate::http::{parse_adopt, reject, valid_tags};
use crate::identity::{CiKeyPayload, NodeKeyPayload, PURPOSE_CI, PURPOSE_NODE};
use crate::subject::{FleetRole, Subject};

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
        .route(
            "/api/v1/nodes/{name}",
            axum::routing::patch(update_node).delete(delete_node),
        )
        .route("/api/v1/nodes/pending/{code}", post(decide_pending))
        .route("/api/v1/boards", get(boards))
        .route("/api/v1/boards/power-cycle", post(power_cycle))
        .route("/api/v1/leases", get(leases))
        .route("/api/v1/leases/{lease_id}", delete(release_lease))
        .route("/api/v1/grants", get(grants).post(create_grant))
        .route("/api/v1/grants/{id_prefix}", delete(revoke_grant))
        .route("/api/v1/grants/limits", get(grant_limits))
        .route("/api/v1/auth-keys", get(auth_keys).post(create_auth_key))
        .route("/api/v1/auth-keys/{hash_prefix}", delete(revoke_auth_key))
        .route("/api/v1/audit", get(audit))
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// An authenticated `/api/v1` caller and the org it acts in.
struct ApiCall {
    caller: Caller,
    subject: Subject,
}

/// Authenticate an `/api/v1` request, accepting the session cookie, and
/// resolve the acting org (`?org=`, default the personal org; membership
/// checked).
///
/// Authentication is forgs' [`forgs_http::authenticate_request`] — still the
/// only place a caller is built from wire input. `TokenKind::Session` only: a
/// node or workload token has no business on the browser API. The cookie is
/// accepted only because `uri`'s path lies under the configured
/// `cookie_api_prefix` (`/api/v1/`), which forgs checks.
async fn api_auth(
    coord: &Coordinator,
    uri: &Uri,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<ApiCall, Response> {
    let caller = crate::http::authenticate(
        coord,
        headers,
        uri.path(),
        &[TokenKind::Session],
        Carrier::ApiCookie,
    )
    .await?;
    let org = crate::http::org_param(query);
    let subject = crate::http::acting_subject(coord, &caller, org.as_deref()).await?;
    Ok(ApiCall { caller, subject })
}

/// Authenticate a **mutating** `/api/v1` call: [`api_auth`] plus the CSRF gate.
///
/// One function rather than a two-line preamble copied into each handler.
/// That is not tidiness: three hand-written copies of a security check is the
/// shape that drifts, and the drift here is silent — a handler that forgot the
/// check would pass every one of its own tests and be exploitable only
/// cross-site. A mutating handler that does not call this has no CSRF
/// protection at all, so `grep mutating_auth` against the router's mutating
/// routes is the whole audit.
///
/// The check is a no-op for a bearer-authenticated call, because that
/// credential is not ambient; [`forgs_http::auth::require_csrf`] owns that
/// distinction. The CSRF check runs **before** the acting org is resolved, so
/// a forged request learns nothing about memberships.
async fn mutating_auth(
    coord: &Coordinator,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<ApiCall, Response> {
    let caller = mutating_caller(coord, method, uri, headers).await?;
    let org = crate::http::org_param(query);
    let subject = crate::http::acting_subject(coord, &caller, org.as_deref()).await?;
    Ok(ApiCall { caller, subject })
}

/// The authentication + CSRF half of [`mutating_auth`], without resolving the
/// acting org — for a handler that must audit a refused org claim itself
/// ([`decide_pending`]).
async fn mutating_caller(
    coord: &Coordinator,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Caller, Response> {
    let caller = crate::http::authenticate(
        coord,
        headers,
        uri.path(),
        &[TokenKind::Session],
        Carrier::ApiCookie,
    )
    .await?;
    // A mutating route is never GET; treat any method as mutating here so a
    // mis-routed GET cannot skip the gate.
    let method = if matches!(*method, Method::GET | Method::HEAD) {
        &Method::POST
    } else {
        method
    };
    if let Err(response) =
        forgs_http::auth::require_csrf(coord.auth(), method, headers, &caller).await
    {
        warn!(subject = %caller.auth.subject, "a cookie-authenticated mutating call had no valid CSRF header");
        return Err(response);
    }
    Ok(caller)
}

/// Map a forgs service error onto the one rejection shape.
fn api_error(e: &forgs_http::ApiError) -> Response {
    reject(e.status(), e.code())
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
    /// The namespace part of the key, if any (`null` for a user).
    org: Option<String>,
    kind: String,
    id: String,
}

impl From<&Subject> for SubjectView {
    fn from(subject: &Subject) -> Self {
        Self::from(subject.key())
    }
}

impl From<&SubjectKey> for SubjectView {
    fn from(key: &SubjectKey) -> Self {
        Self {
            key: key.to_string(),
            org: key.ns().map(str::to_owned),
            kind: key.kind().to_string(),
            id: key.id().to_owned(),
        }
    }
}

/// One row of `GET /api/v1/boards`.
#[derive(Debug, Serialize)]
struct BoardView {
    board: BoardKeyView,
    node: String,
    chip: String,
    /// Board model (board type), e.g. `nrf52840dk` — what `board=<model>`
    /// selects. `null` for a board that declared none (every adopted board).
    model: Option<String>,
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
            node: b.node.0,
            chip: b.chip,
            model: b.model,
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
            owner: n.row.owner_user_id.map(|u| u.to_string()),
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
    /// The immutable user id (`ULID`).
    user_id: String,
    /// The current username, for display.
    username: Option<String>,
    /// Every org the user is a member of, with its name and the user's role.
    memberships: Vec<MembershipView>,
    /// The org this request acted in (`?org=`, default the personal org), or
    /// `null` when that org is not one the user belongs to.
    org: Option<OrgView>,
    /// The session's expiry. The UI needs it to bounce to a fresh login
    /// *before* the next call 401s (`docs/web-ui.md` D1).
    expires: Option<u64>,
}

/// One membership of `GET /api/v1/session`.
#[derive(Debug, Serialize)]
struct MembershipView {
    id: String,
    name: Option<String>,
    role: &'static str,
}

/// `GET /api/v1/org`'s body.
#[derive(Debug, Serialize)]
struct OrgView {
    id: String,
    /// The org's current path (display name).
    name: Option<String>,
    role: &'static str,
}

/// One row of `GET /api/v1/org/members`.
#[derive(Debug, Serialize)]
struct MemberView {
    user_id: String,
    username: Option<String>,
    role: &'static str,
}

/// One `AllowedOp`, with where it is actually enforced.
///
/// `docs/web-ui.md` §6.5 is honest about this and §3 requires the UI to be too:
/// only three of the six labels are enforced anywhere, and a picker that
/// rendered all six identically would read as a permission system it is not.
/// Shipping the fact as a **field** rather than as prose in this doc comment is
/// deliberate: a frontend that re-derived the table would drift from
/// [`AllowedOp::is_enforced`] the first time an op moved.
#[derive(Debug, Serialize)]
struct OpView {
    /// The wire label, as `POST /api/v1/grants` accepts it.
    op: &'static str,
    /// `agent`, `coordinator`, or `nobody` — who checks it at use time.
    ///
    /// `nobody` is not a euphemism: `flash` / `erase` / `reset` travel in band
    /// inside an open data channel that the fleet relays without parsing, so
    /// recording them is intent and audit, never a control.
    enforced_by: &'static str,
    /// Whether granting this op implies [`AllowedOp::Attach`], because it is
    /// unusable without a data channel. `normalize_ops` adds it server-side;
    /// the UI shows the implication, as the CLI does.
    implies_attach: bool,
}

impl From<AllowedOp> for OpView {
    fn from(op: AllowedOp) -> Self {
        Self {
            op: op.as_str(),
            enforced_by: match op {
                AllowedOp::Attach | AllowedOp::Gdb => "agent",
                AllowedOp::PowerCycle => "coordinator",
                AllowedOp::Flash | AllowedOp::Erase | AllowedOp::Reset => "nobody",
            },
            implies_attach: op.needs_data_channel(),
        }
    }
}

/// `GET /api/v1/grants/limits`' body — the endpoint contract, as data.
///
/// Every bound `POST /api/v1/grants` enforces, plus the op semantics, in a
/// shape the frontend reads instead of duplicating. `docs/web-ui.md` §3 asks
/// for exactly this: #3540 has to constrain a date picker to
/// [`Coordinator::MAX_GRANT_TTL_SECS`] and refuse a past date, and a hardcoded
/// `365` in JavaScript is a number that goes stale silently — the picker keeps
/// offering a year while the server starts refusing it, and the operator sees
/// an unexplained `400`.
///
/// Unauthenticated?  No: it is member-gated like the listing it describes.
/// These are not secrets, but an anonymous endpoint that reports a
/// deployment's policy constants is a fingerprinting surface for nothing in
/// return.
#[derive(Debug, Serialize)]
struct GrantLimitsView {
    /// Maximum lifetime, in seconds, of a grant created over this API.
    max_ttl_secs: u64,
    /// Whether `expires` may be omitted. Always `false`; present so the
    /// frontend expresses the rule as a check against the contract rather than
    /// as an assumption.
    expires_optional: bool,
    /// The earliest acceptable `expires`, as epoch seconds: the server's *now*.
    ///
    /// An expiry at or before this is refused (`core.rs`'s `expires <= now`).
    /// Sent because a browser's clock is not the coordinator's, and the
    /// difference is exactly what turns "one minute from now" into a `400`.
    now: u64,
    /// The op vocabulary, with each op's enforcement reality.
    ops: Vec<OpView>,
    /// The minimum revocation-prefix length shared by grants and auth keys.
    min_revoke_prefix: usize,
    /// Maximum auth-key TTL, in seconds — the same contract for
    /// `POST /api/v1/auth-keys`, whose `ttl_secs = 0` is a `400`.
    auth_key_max_ttl_secs: u64,
}

/// One row of `GET /api/v1/grants`, and the body of `POST /api/v1/grants`.
///
/// [`GrantSummary`] serializes acceptably already, but is re-shaped here for
/// the reason every other view struct is: it is a **wire** DTO, and a field
/// added for the CLI's benefit must not silently appear in a browser response.
/// `subject` is flattened through [`SubjectView`] so the frontend has one
/// opaque key plus the parts, exactly as elsewhere.
#[derive(Debug, Serialize)]
struct GrantView {
    id: String,
    org: String,
    /// Who the hardware is shared with.
    subject: SubjectView,
    /// The **canonical** selector string, as `Constraint`'s `Display` renders
    /// it — not the string the caller sent.
    selector: String,
    /// The stored op set, after `normalize_ops`: sorted, deduplicated, and with
    /// `attach` added if a data-plane op needed it.
    ops: Vec<&'static str>,
    expires: Option<u64>,
    /// The creating user, or `null` for a row created outside the API. Only an
    /// org admin can revoke one of those, and the frontend needs to know which
    /// rows those are to render the difference.
    created_by: Option<String>,
    created_at: u64,
}

impl From<GrantSummary> for GrantView {
    fn from(g: GrantSummary) -> Self {
        Self {
            id: g.id,
            org: g.org.0,
            subject: SubjectView::from(&g.subject),
            selector: g.selector,
            ops: g.ops.iter().map(|o| o.as_str()).collect(),
            expires: g.expires,
            created_by: g.created_by,
            created_at: g.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/session` — who the caller is.
///
/// The first call any page makes. Membership in the requested org is **not**
/// required: a session whose membership was revoked must still be able to
/// learn that it has none, or the UI has no way to render anything but a
/// blank 403. `org` is then `null`.
async fn session(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let caller = match crate::http::authenticate(
        &coord,
        &headers,
        uri.path(),
        &[TokenKind::Session],
        Carrier::ApiCookie,
    )
    .await
    {
        Ok(c) => c,
        Err(response) => return response,
    };
    let Some(user) = caller.user_id() else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let username = match coord.db().forgs().user_by_id(user).await {
        Ok(u) => u.map(|u| u.username),
        Err(e) => {
            warn!(error = %e, "failed to resolve a username for display");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let orgs = match coord.db().orgs_of_user(user).await {
        Ok(orgs) => orgs,
        Err(e) => {
            warn!(error = %e, "failed to list memberships");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let mut memberships = Vec::with_capacity(orgs.len());
    for (org, role) in orgs {
        memberships.push(MembershipView {
            name: coord.db().org_name(&org).await.ok().flatten(),
            id: org.0,
            role: role.as_str(),
        });
    }
    // The acting org, if the caller may act in it; a refusal is not an error
    // here (see above).
    let requested = crate::http::org_param(query.as_deref());
    let org = match crate::http::acting_subject(&coord, &caller, requested.as_deref()).await {
        Ok(subject) => {
            let org = subject.org().cloned();
            match org {
                Some(org) => memberships.iter().find(|m| m.id == org.0).map(|m| OrgView {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    role: m.role,
                }),
                None => None,
            }
        }
        Err(_) => None,
    };
    Json(SessionView {
        user_id: user.to_string(),
        username,
        memberships,
        org,
        expires: caller.auth.expires,
    })
    .into_response()
}

/// `POST /api/v1/session/logout` — destroy the caller's own session.
///
/// Deletes exactly the row the caller authenticated with — never one named in
/// the request — so the worst a successful forgery could achieve is logging
/// somebody out (and the CSRF gate stops that too).
///
/// `204` with both cookies cleared, whether or not the row was there: a
/// caller must not be able to distinguish "logged out" from "already gone".
/// A storage failure, however, is a `500`: the session is still live.
async fn logout(
    State(coord): State<Arc<Coordinator>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = match crate::http::authenticate(
        &coord,
        &headers,
        uri.path(),
        &[TokenKind::Session],
        Carrier::ApiCookie,
    )
    .await
    {
        Ok(c) => c,
        Err(response) => return response,
    };
    if let Err(response) =
        forgs_http::auth::require_csrf(coord.auth(), &method, &headers, &caller).await
    {
        return response;
    }
    let request = forgs::api::LogoutRequest::default();
    if let Err(e) = forgs_http::session::logout(coord.auth(), &caller, &request).await {
        return api_error(&e);
    }
    forgs_http::cookies::with_cookies(
        StatusCode::NO_CONTENT.into_response(),
        &forgs_http::cookies::cleared_session_cookies(coord.auth()),
    )
}

/// `GET /api/v1/org` — the acting org.
///
/// Member-gated by [`api_auth`]'s acting-org resolution: an authenticated
/// non-member learns nothing about the org it names.
async fn org(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { caller, subject } = match api_auth(&coord, &uri, &headers, query.as_deref()).await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    let (Some(org), Some(user)) = (subject.org().cloned(), caller.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let role = match coord.db().role_of(&org, user).await {
        Ok(Some(role)) => role,
        Ok(None) => return reject(StatusCode::FORBIDDEN, "forbidden"),
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let name = match coord.db().org_name(&org).await {
        Ok(name) => name,
        Err(e) => {
            warn!(error = %e, "failed to resolve an org name");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    Json(OrgView {
        id: org.0,
        name,
        role: role.as_str(),
    })
    .into_response()
}

/// `GET /api/v1/org/members` — the org's membership, read-only in v1
/// (management is forgs' `/auth/members`).
async fn org_members(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_members_core(&subject).await {
        Ok(members) => Json(
            members
                .into_iter()
                .map(|m| MemberView {
                    user_id: m.user_id.to_string(),
                    username: m.username,
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
/// Exists because `ctl list` is board-shaped and a machine that has plugged in
/// no probes is invisible to it. The CLI now asks the same question over the
/// wire (`ctl nodes` / `SidecarToCoord::ListNodes`), and both paths go through
/// [`Coordinator::list_nodes_core`], so they cannot drift on who may see a
/// node.
///
/// [`NodeView`] is nonetheless kept **separate** from the wire's
/// `fleet_proto::admin::NodeSummary`: this body is the web UI's contract (its
/// `id` and `adopt` are already flattened to strings) and must be free to
/// evolve on the browser's schedule rather than on `PROTOCOL_VERSION`'s. The
/// two renderings happen to agree today; that is not a guarantee either way.
async fn nodes(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_nodes_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(NodeView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// The body of `PATCH /api/v1/nodes/{name}`.
///
/// Every field is optional and an absent one means "leave it alone": the
/// browser sends a partial document, so `{"tags":[]}` clearing the tags and
/// `{}` changing nothing have to be distinguishable, which is what the
/// `Option`s buy.
///
/// `name` is present **so that it can be refused**. See [`update_node`].
///
/// `deny_unknown_fields` so the refusal is uniform: without it `{"name":…}` is
/// a `400` while a typo'd `{"nmae":…}` is a silent success that changes
/// nothing, which is the worse half of both answers. A caller who misspells a
/// field learns it, and a caller who spells `name` correctly still learns that
/// renaming is refused rather than unsupported.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    adopt: Option<String>,
}

/// `PATCH /api/v1/nodes/{name}` — a node's tags and adoption policy.
///
/// Owner-or-admin (`docs/web-ui.md` §7); the policy and its sharp edge — a
/// node with `owner_user_id = NULL` is admin-only — live in
/// [`Coordinator::update_node_core`], not here.
///
/// # Renaming is refused, loudly
///
/// A `name` field is a `400 invalid_request`, **not** a silent no-op. The node
/// id is `{org}/{name}`, `board.node_id` references it under enforced foreign
/// keys, `leases.node_id` carries it with no foreign key at all, and every live
/// `BoardRef` in the scheduler embeds it; refusing is the v1 answer
/// (`docs/web-ui.md` §3, amended by this change to record it). Ignoring the
/// field instead would leave an operator believing a rename had happened while
/// their `boards.toml`, their scripts and the audit log all disagreed.
///
/// # Validation is the existing validation
///
/// `tags` goes through [`crate::http::valid_tags`] and `adopt` through
/// [`crate::http::parse_adopt`] — the same functions the enrollment paths use,
/// not a copy. `docs/web-ui.md` §5's claim that every piece of
/// attacker-controlled text this UI renders is server-side charset-validated is
/// only true while there is one implementation of the charset.
async fn update_node(
    State(coord): State<Arc<Coordinator>>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let Ok(patch) = serde_json::from_slice::<NodePatch>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if patch.name.is_some() {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if patch.tags.as_deref().is_some_and(|t| !valid_tags(t)) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // `parse_adopt`'s default is never reached: `None` is already "leave it
    // alone" and is mapped to `None` below, so the sentinel only has to be a
    // value, not a meaningful one.
    let adopt = match patch.adopt.as_deref() {
        None => None,
        Some(label) => match parse_adopt(Some(label), AdoptPolicy::Declared) {
            Ok(adopt) => Some(adopt),
            Err(response) => return response,
        },
    };
    match coord
        .update_node_core(&subject, &name, patch.tags.as_deref(), adopt)
        .await
    {
        Ok(node) => Json(NodeView::from(node)).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `DELETE /api/v1/nodes/{name}` — de-enroll a machine.
///
/// A **revocation**, not a tidy-up: deleting the `node` row invalidates the
/// node's token (architecture §4.2), and the cascade that makes that real —
/// live leases through the whole release path, boards out of the scheduler and
/// the `board` table, and the node's control-plane `WebSocket` actually closed
/// (not merely unrouted) — lives in
/// [`Coordinator::delete_node_core`], which is where a reader looking for "what
/// else does this touch?" should go.
///
/// `204` with no body on success. There is nothing useful to return, and a body
/// describing the deleted node would be a small existence oracle for the next
/// caller who retries.
async fn delete_node(
    State(coord): State<Arc<Coordinator>>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    match coord.delete_node_core(&subject, &name).await {
        Ok(_id) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => op_error(&e),
    }
}

/// The body of `POST /api/v1/nodes/pending/{code}`.
///
/// The code travels in the path, so this carries only the decision. `replace`
/// defaults to `false` and the refusal it guards is enforced by
/// [`crate::http::decide_pending_node`], not here: the requesting machine chose
/// its `node_name` before any org existed, so without the guard an approver
/// could be talked into silently re-credentialing a production node.
#[derive(Debug, Deserialize)]
struct PendingDecision {
    decision: NodeApprovalDecision,
    #[serde(default)]
    replace: bool,
}

/// `POST /api/v1/nodes/pending/{code}` — inspect, approve or deny a pending
/// node registration.
///
/// This is `docs/architecture.md` §4.2's commitment being cashed in: approval is
/// a pure function of `(code, decision, authenticated user)`, and
/// [`crate::http::decide_pending_node`] takes an already-resolved subject
/// *precisely* so a cookie-authenticated handler could exist without a second
/// binding site. It is called here **unchanged**. Membership suffices, exactly
/// as on `POST /node/register/approve`, and the `node.approve.denied` audit row
/// for a non-member is the same one — this handler reuses that route's check
/// rather than writing a second opinion about who may approve.
///
/// # The phishing warning the frontend must show
///
/// The `inspect` response describes a machine the approver **cannot see**. RFC
/// 8628 §5.4's mitigation is that they are told so before they decide, and the
/// CLI prints it verbatim (`fleet-bin`'s `node approve`). The JSON API carries
/// it in the `inspect` response body as a `warning` field, whose value is the
/// constant [`APPROVAL_WARNING`]:
///
/// > Approving grants this machine access to hardware in your org, and you
/// > cannot see it from here. Approve ONLY if you started this enrollment.
///
/// **The frontend (#3540) must render that string verbatim in the approval
/// form, next to the confirm button.** It is not decoration and it is not the
/// frontend's to reword: it is the only control standing between a phoned-in
/// code and hardware access in the approver's org. It ships as a server-sent
/// field rather than as prose in this doc comment so that a frontend which
/// forgets to show it is showing a visibly empty box rather than silently
/// dropping the mitigation.
///
/// # There is no listing endpoint to pair with this
///
/// `GET /api/v1/nodes/pending` is deliberately absent; see the module
/// documentation and `docs/web-ui.md` §4.
async fn decide_pending(
    State(coord): State<Arc<Coordinator>>,
    Path(code): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let caller = match mutating_caller(&coord, &method, &uri, &headers).await {
        Ok(c) => c,
        Err(response) => return response,
    };
    // Membership in the acting org is checked — and a refusal audited as
    // `node.approve.denied` — exactly as `POST /node/register/approve` does
    // it: two surfaces onto one ceremony must not disagree about who may
    // perform it, nor about what the record of a refusal looks like.
    let org = crate::http::org_param(query.as_deref());
    let subject = match crate::http::acting_subject(&coord, &caller, org.as_deref()).await {
        Ok(s) => s,
        Err(response) => {
            crate::http::audit_denied(&coord, &caller, "node.approve.denied").await;
            return response;
        }
    };
    let Ok(request) = serde_json::from_slice::<PendingDecision>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let response = crate::http::decide_pending_node(
        &coord,
        &subject,
        &code,
        request.decision,
        request.replace,
    )
    .await;
    decorate_pending(response, request.decision).await
}

/// The verbatim warning an approval form must show; see [`decide_pending`].
///
/// Byte-identical to the sentence `probe-rs-fleet node approve` prints, so the
/// two surfaces of one ceremony say the same thing. Both halves are
/// load-bearing: the first says what is being granted, the second says the only
/// safe reason to grant it.
pub(crate) const APPROVAL_WARNING: &str =
    "Approving grants this machine access to hardware in your org, and you \
     cannot see it from here. Approve ONLY if you started this enrollment.";

/// Attach [`APPROVAL_WARNING`] to a successful `inspect` response.
///
/// Done by re-shaping the JSON rather than by widening
/// `fleet_proto::auth_api::NodeApprovalResponse`: that type is the **wire** contract
/// the CLI parses, and growing it for the browser's benefit would put a
/// browser-shaped field in the shared crate — the drift `docs/web-ui.md` D2
/// exists to prevent. A non-200, or a body that is not the object we expect, is
/// passed through untouched.
async fn decorate_pending(response: Response, decision: NodeApprovalDecision) -> Response {
    use axum::body::to_bytes;

    if decision != NodeApprovalDecision::Inspect || response.status() != StatusCode::OK {
        return response;
    }
    let (parts, body) = response.into_parts();
    // The body is one small JSON object this process just produced; the cap is
    // a bound, not a policy.
    let Ok(bytes) = to_bytes(body, 64 * 1024).await else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let Ok(serde_json::Value::Object(mut object)) = serde_json::from_slice(&bytes) else {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    };
    object.insert(
        "warning".to_owned(),
        serde_json::Value::String(APPROVAL_WARNING.to_owned()),
    );
    Json(serde_json::Value::Object(object)).into_response()
}

/// `GET /api/v1/boards` — the same inventory `ctl list` renders.
async fn boards(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.list_boards_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(BoardView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/leases` — the same table `ctl who` renders.
async fn leases(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.who_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(LeaseView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `POST /api/v1/boards/power-cycle` — cut and restore a board's power.
///
/// The board travels **in the body**, not in the path: a [`BoardRef`] is four
/// slash-separated segments (`docs/web-ui.md` §3), so board-targeting endpoints
/// take the node-local name (or a qualified one, per §6.5's
/// `BoardRef::answers_to` grammar) exactly as the wire verbs do.
///
/// [`Coordinator::operator_power_cycle_core`] resolves it within the caller's
/// [`fleet_core::access::Access`] through the tiered `resolve_board` — own org
/// wins, then granted orgs — and re-checks [`AllowedOp::PowerCycle`] for a
/// grantee. That second check is not redundant: resolution proves the caller may
/// *see* the board, not that they may cut its power, and this is the one op the
/// **coordinator** enforces rather than the node (the node's power-cycle
/// command carries no capability token to check).
///
/// A board in another tenant is a `404`, identical to one that does not exist.
async fn power_cycle(
    State(coord): State<Arc<Coordinator>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let Ok(request) = serde_json::from_slice::<PowerCycleRequest>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if request.board.trim().is_empty() {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let board = BoardName(request.board.trim().to_owned());
    match coord.operator_power_cycle_core(&subject, &board).await {
        Ok(board) => Json(PowerCycledView { board: board.0 }).into_response(),
        Err(e) => op_error(&e),
    }
}

/// The body of `POST /api/v1/boards/power-cycle`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerCycleRequest {
    /// A node-local board name, or a qualified one.
    board: String,
}

/// `POST /api/v1/boards/power-cycle`'s body.
#[derive(Debug, Serialize)]
struct PowerCycledView {
    /// The node-local name the request resolved to, echoed back — which is how
    /// a caller who sent a bare name learns *which* board was cycled.
    board: String,
}

/// `DELETE /api/v1/leases/{lease_id}` — release a lease.
///
/// [`Coordinator::release_lease_core`]'s `require_lease_control` gives
/// holder-or-admin, and "admin" here means the **board org's** admin: reclaiming
/// your own hardware from somebody you shared it with is the case this exists
/// for.
///
/// A stranger gets exactly the answer they would get for a lease that does not
/// exist (`AuthzError::lease_message`, mapped to `404 not_found`). Telling the
/// two apart would let anyone probe which lease ids are live and, across orgs,
/// enumerate other tenants' leases.
///
/// The id is a `u64` in the path — the one identifier on this surface that is
/// not a name, and the only reason it may be there at all is that it contains
/// no slash. A non-numeric segment is a `400`, not a `404`: it is a malformed
/// request rather than an answer about whether a lease exists.
async fn release_lease(
    State(coord): State<Arc<Coordinator>>,
    Path(lease_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let Ok(lease) = lease_id.parse::<u64>() else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    match coord.release_lease_core(&subject, LeaseId(lease)).await {
        Ok(lease) => Json(ReleasedView { lease: lease.0 }).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `DELETE /api/v1/leases/{lease_id}`'s body.
#[derive(Debug, Serialize)]
struct ReleasedView {
    lease: u64,
}

/// `GET /api/v1/grants` — the grants this org has issued.
///
/// **Member**-gated, unlike creation. That divergence from auth keys (where
/// membership suffices for both) is deliberate and lives in the cores: a
/// listing names only grants the org itself issued, which any member can
/// already infer from `ctl list` / `ctl who`.
///
/// This is the outbound view. There is deliberately no "what am I granted?"
/// endpoint; `GET /api/v1/boards` is the grantee-facing one.
async fn grants(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    match coord.grant_list_core(&subject).await {
        Ok(rows) => Json(rows.into_iter().map(GrantView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `GET /api/v1/grants/limits` — the bounds `POST /api/v1/grants` enforces.
///
/// See [`GrantLimitsView`] for why this is a route rather than prose in
/// `docs/web-ui.md`. Member-gated, like the listing it describes.
async fn grant_limits(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let Some(org) = subject.org().cloned() else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let Ok(()) = crate::authz::require_role(coord.db(), &subject, &org, FleetRole::Member).await
    else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    Json(GrantLimitsView {
        max_ttl_secs: Coordinator::MAX_GRANT_TTL_SECS,
        expires_optional: false,
        now: coord.now(),
        ops: AllowedOp::all().into_iter().map(OpView::from).collect(),
        min_revoke_prefix: forgs_http::keys::MIN_PREFIX_LEN,
        auth_key_max_ttl_secs: coord.auth().ttl().api_key_max,
    })
    .into_response()
}

/// The body of `POST /api/v1/grants`.
///
/// `deny_unknown_fields`, as everywhere on this surface: a typo'd field that
/// silently created a *different* grant than the caller described is the worst
/// possible failure mode for the one verb that hands hardware outward.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    /// The grantee, in one of `grant_create`'s four spellings
    /// (`repo:<owner>/<name>`, a rendered `SubjectKey`, a bare `gh-<id>`, or a
    /// GitHub login). Resolved server-side to an **immutable user id**.
    subject: String,
    /// The canonical selector string — the same one a CLI would send.
    selector: String,
    /// `AllowedOp` labels; see [`OpView`].
    ops: Vec<String>,
    /// Expiry, as epoch seconds. Required, and bounded on both ends; see
    /// [`GrantLimitsView`].
    expires: Option<u64>,
}

/// `POST /api/v1/grants` — share this org's hardware with another subject.
///
/// **Admin**-gated inside [`Coordinator::grant_create_core`], which also holds
/// every rule this handler deliberately does not pre-empt:
///
/// * the **selector** is parsed by `fleet_proto::lease::parse_constraint`
///   (where a bare term is a tag) and stored as `Constraint`'s `Display`, so a
///   grant's
///   meaning never depends on which surface wrote it. The UI sends the same
///   string a CLI would and must **not** build a structured selector of its
///   own. An empty expression is refused, which is what stops an empty tag set
///   — a match-everything — from reaching the table;
/// * the **ops** go through `fleet_proto::token::normalize_ops`, so a
///   data-plane op implies `attach` in the stored row;
/// * the **expiry** is required, must be in the future, and is capped at
///   [`Coordinator::MAX_GRANT_TTL_SECS`];
/// * the **grantee** is resolved now, to an immutable id, so §6.4's
///   rename/reuse takeover is not a hole.
///
/// This handler parses op *labels* only — the one thing the core cannot do,
/// because its signature takes [`AllowedOp`]s. An unrecognised label is a `400`
/// rather than a silently dropped op.
async fn create_grant(
    State(coord): State<Arc<Coordinator>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let Ok(request) = serde_json::from_slice::<GrantRequest>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(ops) = request
        .ops
        .iter()
        .map(|o| AllowedOp::from_label(o))
        .collect::<Option<Vec<_>>>()
    else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    match coord
        .grant_create_core(
            &subject,
            &request.subject,
            &request.selector,
            ops,
            request.expires,
        )
        .await
    {
        Ok(grant) => Json(GrantView::from(grant)).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `DELETE /api/v1/grants/{id_prefix}` — revoke a grant, for real.
///
/// Creator-or-admin, including the `created_by = NULL` rows only an admin can
/// reach; the policy is [`Coordinator::grant_revoke_core`]'s, along with the
/// part that matters more than the row deletion: the **cascade**. Revoking
/// recomputes the grantee's access and tears down, through the whole release
/// path, every lease they hold on a board they may no longer use. Deleting the
/// row alone would leave them relaying bytes until the lease TTL ran out while
/// the operator believed the grant was gone.
///
/// A grant id is hex (or `ci-` + hex), so it is safe in a path; the core still
/// refuses a prefix shorter than 8 characters of entropy, because
/// `delete_grants_by_prefix("")` is `LIKE '%'`.
async fn revoke_grant(
    State(coord): State<Arc<Coordinator>>,
    Path(id_prefix): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    match coord.grant_revoke_core(&subject, &id_prefix).await {
        Ok(ids) => Json(RevokedGrantsView { revoked: ids }).into_response(),
        Err(e) => op_error(&e),
    }
}

/// `DELETE /api/v1/grants/{id_prefix}`'s body.
#[derive(Debug, Serialize)]
struct RevokedGrantsView {
    /// The ids actually deleted — what the operator is shown, since a prefix
    /// that matched one grant still deletes only that grant.
    revoked: Vec<String>,
}

/// `GET /api/v1/auth-keys` — the org's enrollment keys, **hashes only**.
///
/// Membership suffices, exactly as on forgs' `/auth/keys`: the check is
/// [`forgs_http::keys::list`]'s, shared with that route so
/// the two surfaces cannot disagree about who may look, nor leave two
/// differently-named refusals in the audit log. The listing carries no secret —
/// only a key's SHA-256 is stored at all.
async fn auth_keys(
    State(coord): State<Arc<Coordinator>>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { caller, subject } = match api_auth(&coord, &uri, &headers, query.as_deref()).await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    let (Some(org), Some(user)) = (subject.org(), caller.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    match forgs_http::keys::list(coord.auth(), user, &org.0).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => api_error(&e),
    }
}

/// The body of `POST /api/v1/auth-keys`, mirroring `AuthKeyRequest::Create`.
///
/// A local struct rather than the wire enum because the action is in the method
/// here, not in an `action` tag. Every field means what it means on
/// `POST /auth/keys`, and the validation is that route's — see
/// [`create_auth_key`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthKeyCreateRequest {
    #[serde(default)]
    tags: Vec<String>,
    /// Seconds. `0` is a `400` (no forever-keys over the API) and the value is
    /// capped at the configured API-key maximum (`Ttls::api_key_max`).
    ttl_secs: u64,
    #[serde(default)]
    multi_use: bool,
    /// `node` (the default) or `ci`. An unrecognised value is a `400`, never a
    /// silent default: they are different credentials.
    #[serde(default)]
    purpose: Option<String>,
    /// For a `ci` key: the ops its synthesised grant confers.
    #[serde(default)]
    ops: Vec<String>,
    /// For a `ci` key: a stable identity name (`--as` on the CLI).
    ///
    /// A name alongside `purpose: "node"`, or one outside `[a-z0-9._-]`, is a
    /// `400` — the validation is [`forgs_http::keys::create`]'s, as
    /// everything else here is.
    #[serde(default)]
    subject_name: Option<String>,
}

/// `POST /api/v1/auth-keys` — mint an enrollment key.
///
/// # This response contains a long-lived secret, exactly once
///
/// [`forgs::api::ApiKeyCreated`] carries the key itself; only its SHA-256
/// is stored, so it exists in this body and nowhere else, ever. That is the
/// single place the browser surface creates a long-lived bearer secret, and it
/// is a **deliberate, accepted cost** recorded in `docs/web-ui.md` D4: the
/// alternative is a UI in which the most-asked-for enrollment path is the one
/// thing you must leave the browser for. The UI shows it in a panel that says
/// it will not be shown again and stores it nowhere.
///
/// **This is not a capability token, so it does not violate the
/// no-capability-token rule**, and this paragraph exists so a later reader does
/// not "fix" it. A capability token is offline-verifiable, unrevokable short of
/// tearing down its lease, and confers control of a *leased board*. An auth key
/// is org-scoped, expiring (30 days maximum here), listable, revocable — with
/// the revocation cascading through any grant it synthesised — and confers only
/// the right to *enroll*: a `node` key adds a machine that offers probes, a `ci`
/// key redeems into a workload token bounded by its own tag selector.
///
/// # The validation is `/auth/keys`'s, because it is the same function
///
/// [`forgs_http::keys::create`] is called unchanged, and the payload is
/// checked by `FleetPurposes::check_payload`. Forking it would mean
/// two opinions about `ttl_secs = 0`, the TTL cap, the `purpose` allowlist and
/// the tagless-`ci` refusal — and the tagless-`ci` rule is the one that stops a
/// key from synthesising a grant over the whole fleet.
async fn create_auth_key(
    State(coord): State<Arc<Coordinator>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let ApiCall { caller, subject } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let Ok(request) = serde_json::from_slice::<AuthKeyCreateRequest>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let (Some(org), Some(user)) = (subject.org(), caller.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    // Build the purpose's payload from the flat request; the purpose policy
    // (`FleetPurposes::check_payload`) validates and canonicalises it, so
    // the rules — tagless `ci` refused, ops labels known — live in one place.
    let purpose = request.purpose.as_deref().unwrap_or(PURPOSE_NODE);
    let payload = match purpose {
        PURPOSE_NODE => {
            if !request.ops.is_empty() {
                return reject(StatusCode::BAD_REQUEST, "invalid_request");
            }
            serde_json::to_value(NodeKeyPayload { tags: request.tags })
        }
        PURPOSE_CI => serde_json::to_value(CiKeyPayload {
            tags: request.tags,
            ops: request.ops,
        }),
        _ => return reject(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let Ok(payload) = payload else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    match forgs_http::keys::create(
        coord.auth(),
        user,
        &org.0,
        request.ttl_secs,
        request.multi_use,
        purpose,
        request.subject_name.as_deref(),
        Some(&payload),
    )
    .await
    {
        Ok(created) => Json(created).into_response(),
        Err(e) => api_error(&e),
    }
}

/// `DELETE /api/v1/auth-keys/{hash_prefix}` — revoke enrollment keys.
///
/// Creator-or-admin, mirroring lease ownership and grant revocation: the key's
/// creator may revoke it, an org admin may revoke any of the org's — including
/// the shell-minted rows whose `created_by` is `NULL`, which would otherwise be
/// unrevokable from a browser at all.
///
/// [`forgs_http::keys::revoke`] is called unchanged, so the `≥ 8` hex-digit
/// prefix floor (an empty prefix is `LIKE '%'`, i.e. every key in the org) and
/// the **CI-grant cascade** come along: revoking a `ci` key also revokes the
/// grant its redemption synthesised, through the whole release path, rather
/// than leaving a runner on a board until its lease TTL ran out.
///
/// A hash prefix is hex, so it is safe in a path.
async fn revoke_auth_key(
    State(coord): State<Arc<Coordinator>>,
    Path(hash_prefix): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { caller, subject } =
        match mutating_auth(&coord, &method, &uri, &headers, query.as_deref()).await {
            Ok(v) => v,
            Err(response) => return response,
        };
    let (Some(org), Some(user)) = (subject.org(), caller.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    match forgs_http::keys::revoke(coord.auth(), user, &org.0, &hash_prefix).await {
        Ok(revoked) => Json(revoked).into_response(),
        Err(e) => api_error(&e),
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
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ApiCall { subject, .. } = match api_auth(&coord, &uri, &headers, query.as_deref()).await {
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
        assert_eq!(
            query_value("board=a&board=b", "board").as_deref(),
            Some("a")
        );
    }

    /// A percent-decoder that sliced the `&str` by byte index would panic here,
    /// on input any authenticated session can send and *before* the endpoint's
    /// admin check runs. Pinned rather than left to be re-derived.
    #[test]
    fn a_malformed_escape_decodes_rather_than_panicking() {
        // `%` immediately before a multi-byte character: bytes `i+1`/`i+2` land
        // inside it, which is the char-boundary panic.
        assert_eq!(
            query_value("board=%\u{20ac}x", "board").as_deref(),
            Some("%\u{20ac}x")
        );
        // The same shape in the *key*, which is decoded for every pair.
        assert_eq!(
            query_value("%\u{20ac}x=1&board=ok", "board").as_deref(),
            Some("ok")
        );
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
        assert_eq!(
            query_value("board=%ff", "board").as_deref(),
            Some("\u{fffd}")
        );
    }

    /// A `BoardRef` is four segments, so the flattened key is what a body field
    /// carries; the parts stay available for display.
    #[test]
    fn a_board_key_carries_both_shapes() {
        let board = BoardRef::new(
            fleet_proto::ids::OrgId("gh-1".to_owned()),
            fleet_proto::ids::NodeId("gh-1/rpi-1".to_owned()),
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
                fleet_proto::ids::NodeId("o/n".to_owned()),
                "b",
            ),
            node: fleet_proto::ids::NodeId("o/n".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
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
