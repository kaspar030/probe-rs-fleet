//! The HTTP/`WebSocket` surface (architecture §3.5).
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /healthz` | anyone | liveness, for the proxy |
//! | `GET /agent` | nodes (`prfn1_`) | `WebSocket` upgrade → the node control plane |
//! | `GET /client[?org=]` | users, workloads | `WebSocket` upgrade → the sidecar/ctl plane |
//! | `GET /delegate` | a sandboxed client | `WebSocket` upgrade → a **crippled** relay-only plane |
//! | `/auth/*` | — | forgs' router: login, signup, sessions, refresh, logout, device flow, API keys, members |
//! | `POST /node/register/start` | anyone | begin an approval-pending node registration |
//! | `POST /node/register/poll` | a pending node | redeem an approved registration for a node token |
//! | `POST /node/register/approve` | org members | inspect / approve / deny one |
//! | `POST /node/enroll` | holder of a `node` API key | redeem it for a node token |
//! | `POST /node/self-register` | org members (session) | register the calling machine (`share`) |
//! | `GET /node/approve` | anyone | a static page saying what to run |
//! | `/api/v1/*` | browser sessions (+ `X-Fleet-Csrf`), or a bearer | the JSON API ([`crate::api`]) |
//! | `/`, `/ui*` | anyone | the UI shell and assets ([`crate::assets`]) |
//!
//! **This router has no global fallback and must not grow one.**
//!
//! # Where a caller comes from
//!
//! `forgs_http::authenticate_request` is **the only place a credential
//! becomes a subject.** fleet adds the *acting org* ([`acting_subject`]): a
//! user names one (`?org=` or a body field; default the personal org) and
//! membership there is checked before a [`Subject`] is built. A node acts in
//! its node row's org, a workload in none. The session cookie is accepted on
//! `/api/v1/*` only (forgs' `Carrier::ApiCookie` with fleet's prefix), so a
//! browser can never drive `/agent`, `/client` or `/delegate`.
//!
//! # Interactive node approval
//!
//! forgs owns the user-code / device-secret machine (a pending row with a
//! JSON payload); fleet's [`crate::identity::FleetNodeApprovals`] hook decides
//! who may approve and mints the node token on redemption. The takeover guard
//! (a name that already exists in the target org needs `replace`) lives in
//! [`decide_pending_node`], shared by the CLI route and the browser API.
//! Accepted risks (cross-tenant code guessing bounded by entropy + TTL + audit;
//! unauthenticated row growth bounded by `max_pending_nodes`; RFC 8628 §5.4
//! phishing mitigated by inspect-first) are unchanged.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ws::WebSocketUpgrade, ConnectInfo, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use forgs::TokenKind;
use forgs_http::{Caller, Carrier, JsonBody};
use tracing::{debug, info, warn};

use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::auth_api::{
    NodeApprovalDecision, NodeApprovalRequest, NodeApprovalResponse, NodeEnrollRequest,
    NodeRegisterPollRequest, NodeRegisterStartRequest, NodeRegisterStartResponse,
    SelfRegisterRequest,
};
use probefleet_proto::ids::{NodeId, OrgId};

use crate::core::Coordinator;
use crate::identity::{NodeKeyPayload, PendingNodePayload, PURPOSE_NODE};
use crate::server::NodeAuth;
use crate::state::AuditEntry;
use crate::subject::Subject;

/// Build the coordinator's router: fleet's routes plus forgs' `/auth/*`.
pub fn router(coord: Arc<Coordinator>) -> Router {
    coord.attach();
    let ctx = coord.auth().clone();
    Router::new()
        .route("/healthz", get(healthz))
        .route("/agent", get(node_ws))
        .route("/client", get(client_ws))
        .route("/delegate", get(delegate_ws))
        .route("/node/register/start", post(node_register_start))
        .route("/node/register/poll", post(node_register_poll))
        .route("/node/register/approve", post(node_register_approve))
        .route("/node/enroll", post(node_enroll))
        .route("/node/self-register", post(node_self_register))
        .route("/node/approve", get(node_approve_page))
        .merge(crate::api::router())
        .merge(crate::assets::router())
        .with_state(coord)
        .merge(forgs_http::router().with_state(ctx))
}

/// Liveness probe. Deliberately unauthenticated and content-free.
async fn healthz() -> &'static str {
    "ok"
}

/// The single rejection body (forgs' shape, so the two halves of the server
/// cannot be told apart by their errors).
pub(crate) fn reject(status: StatusCode, code: &str) -> Response {
    forgs_http::reject(status, code)
}

/// The bearer credential of an `Authorization` header.
fn bearer_of(headers: &HeaderMap) -> Option<&str> {
    forgs_http::auth::bearer_of(headers)
}

/// Authenticate through forgs' seam. `path` matters only for
/// [`Carrier::ApiCookie`].
pub(crate) async fn authenticate(
    coord: &Coordinator,
    headers: &HeaderMap,
    path: &str,
    allowed: &[TokenKind],
    carrier: Carrier,
) -> Result<Caller, Response> {
    forgs_http::authenticate_request(coord.auth(), headers, path, allowed, carrier).await
}

/// Resolve the org a **user** acts in and build its [`Subject`].
///
/// `requested` is an org path or id (`?org=`); `None` means the user's
/// personal org. Membership is checked here: an org the caller is not a
/// member of — or one that does not exist — is the same `403`, so the route
/// is not an org-existence oracle. Workloads act in no org; asking for one is
/// a `403`.
pub(crate) async fn acting_subject(
    coord: &Coordinator,
    caller: &Caller,
    requested: Option<&str>,
) -> Result<Subject, Response> {
    let forbidden = || reject(StatusCode::FORBIDDEN, "forbidden");
    let Some(key) = crate::subject::to_proto(caller.subject.key()) else {
        return Err(forbidden());
    };
    let Some(user) = caller.user_id() else {
        if requested.is_some() {
            return Err(forbidden());
        }
        return Ok(Subject::new(key, None));
    };
    let org = match requested.map(str::trim).filter(|r| !r.is_empty()) {
        Some(raw) => match coord.db().resolve_org(raw).await {
            Ok(Some(org)) => org,
            Ok(None) => return Err(forbidden()),
            Err(e) => {
                warn!(error = %e, "failed to resolve an org");
                return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
            }
        },
        None => match coord.db().personal_org(user).await {
            Ok(Some(org)) => org,
            Ok(None) => return Err(forbidden()),
            Err(e) => {
                warn!(error = %e, "failed to resolve the personal org");
                return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
            }
        },
    };
    match coord.db().role_of(&org, user).await {
        Ok(Some(_)) => Ok(Subject::new(key, Some(org))),
        Ok(None) => Err(forbidden()),
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
        }
    }
}

/// The `org` query parameter, if present.
pub(crate) fn org_param(query: Option<&str>) -> Option<String> {
    query.and_then(|q| crate::api::query_value(q, "org"))
}

/// `GET /agent` — a node's persistent control-plane connection. Node tokens
/// only; the org and node id come from the node row the token matched.
async fn node_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let kind = crate::identity::node_token_kind(coord.auth().format());
    let caller = match authenticate(&coord, &headers, "/agent", &[kind], Carrier::Header).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let key = caller.subject.key();
    let (Some(ns), node_id) = (key.ns(), NodeId(key.id().to_owned())) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let org = OrgId(ns.to_owned());
    let auth = NodeAuth::new(
        org.clone(),
        node_id.clone(),
        caller.auth.token_issued_at.unwrap_or(0),
    );
    info!(%node_id, %org, "node connected");

    ws.max_message_size(probefleet_wire::MAX_FRAME_LEN)
        .max_frame_size(probefleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) =
                crate::server::handle_node(coord, Box::new(tx), Box::new(rx), node_id.clone(), auth)
                    .await
            {
                if probefleet_wire::is_benign_close(&e.as_wire()) {
                    debug!(%node_id, "node connection closed");
                } else {
                    debug!(%node_id, error = %e, "node connection closed");
                }
            }
        })
}

/// `GET /client[?org=<path-or-id>]` — a ctl or sidecar connection.
///
/// A user session **or** a CI workload token. The allowlist is the fence
/// that keeps a workload off `/agent` and `/auth/keys`. A user acts in the
/// named org (default personal); the membership is checked at connect and
/// again by every verb.
async fn client_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ws: WebSocketUpgrade,
) -> Response {
    let caller = match authenticate(
        &coord,
        &headers,
        "/client",
        &[TokenKind::Session, TokenKind::Workload],
        Carrier::Header,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let requested = org_param(query.as_deref());
    let subject = match acting_subject(&coord, &caller, requested.as_deref()).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    debug!(%subject, "client connected");

    ws.max_message_size(probefleet_wire::MAX_FRAME_LEN)
        .max_frame_size(probefleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) =
                crate::server::handle_sidecar(coord, Box::new(tx), Box::new(rx), subject).await
            {
                if probefleet_wire::is_benign_close(&e.as_wire()) {
                    tracing::trace!("client connection closed by peer");
                } else {
                    debug!(error = %e, "client connection closed");
                }
            }
        })
}

/// `GET /delegate` — a sandboxed client holding nothing but a capability token.
///
/// The one authenticated route that mints **no subject** (see the module
/// docs). The bearer is the hex-encoded wire form of a
/// [`probefleet_proto::token::SignedToken`]; the coordinator verifies the signature
/// with its own key — it minted the token, so no new key material is involved
/// — and checks expiry. Everything else the connection may do is enforced by
/// [`crate::server::handle_delegate`]'s message allowlist.
///
/// Every failure is the same flat `401`: a caller learns its token did not
/// work, never why. The reason is logged, not returned. There is no audit row,
/// for the reason the module docs give — a rejected token has no resolvable
/// org, and `audit_log.org_id` is `NOT NULL` on purpose.
async fn delegate_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    use probefleet_proto::token::{SignedToken, TokenVerifier as _};

    let bearer = bearer_of(&headers).unwrap_or("");
    let Some(wire) = decode_hex(bearer) else {
        debug!("delegate: bearer is not a hex capability token");
        return reject(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let Ok(signed) = SignedToken::from_wire(&wire) else {
        debug!("delegate: bearer is too short to be a signed token");
        return reject(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let token = match coord.signer().verify(&signed) {
        Ok(token) => token,
        Err(e) => {
            debug!(error = %e, "delegate: token did not verify");
            return reject(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    };
    if !token.is_valid_at(coord.now()) {
        debug!(lease = ?token.lease, "delegate: token expired");
        return reject(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // The lease must still be live. Revocation of a delegation *is* releasing
    // the lease, so this check is what makes that revocation immediate rather
    // than "once the token expires".
    {
        let sched = coord.scheduler().lock().await;
        if sched.lease_holder(token.lease).is_none() {
            debug!(lease = ?token.lease, "delegate: lease is no longer live");
            return reject(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    }
    debug!(lease = ?token.lease, board = %token.board, "delegated connection");

    ws.max_message_size(probefleet_wire::MAX_FRAME_LEN)
        .max_frame_size(probefleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) =
                crate::server::handle_delegate(coord, Box::new(tx), Box::new(rx), token).await
            {
                if probefleet_wire::is_benign_close(&e.as_wire()) {
                    tracing::trace!("delegated connection closed by peer");
                } else {
                    debug!(error = %e, "delegated connection closed");
                }
            }
        })
}

/// Decode a lowercase/uppercase hex string into bytes.
///
/// Local rather than a dependency: the only hex the coordinator decodes is a
/// delegated capability token.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Maximum length of a node name accepted at registration.
const MAX_NODE_NAME_LEN: usize = 64;
/// Maximum length of one selection tag accepted at registration.
const MAX_TAG_LEN: usize = 32;
/// Maximum number of tags accepted at registration.
const MAX_TAGS: usize = 16;

/// Whether a node name is acceptable to store.
///
/// 1–[`MAX_NODE_NAME_LEN`] characters of `[A-Za-z0-9._-]`. Two independent
/// reasons, both load-bearing:
///
/// * the name lands inside the node id via `node_id_for` (`"<org>/<name>"`), so
///   `/`, whitespace and control characters are already meaningful there; and
/// * on the interactive-approval path the name arrives from an
///   **unauthenticated** request and is then rendered into a human approver's
///   terminal. ANSI escapes or newlines in it could repaint or scroll away the
///   "approve only if you started this enrollment" warning that is the whole
///   RFC 8628 §5.4 mitigation.
///
/// Applied at **registration time only**, never at authentication: an existing
/// node row with an odd name keeps working.
fn valid_node_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NODE_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Whether a tag list is acceptable to store. Same charset as a node name, at
/// most [`MAX_TAGS`] tags of [`MAX_TAG_LEN`] characters.
///
/// `pub(crate)` so [`crate::api`]'s `PATCH /api/v1/nodes/{name}` validates tags
/// with **this** function rather than a second copy of the rule. The charset is
/// what `docs/web-ui.md` §5 leans on for "every piece of attacker-controlled
/// text this UI renders is server-side charset-validated", and a divergent
/// copy would erode exactly that claim while still passing its own tests.
pub(crate) fn valid_tags(tags: &[String]) -> bool {
    tags.len() <= MAX_TAGS
        && tags.iter().all(|t| {
            !t.is_empty()
                && t.len() <= MAX_TAG_LEN
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        })
}

/// Parse an `adopt` label, or produce the `400` for an unrecognised one.
///
/// `None` means this grant's default. A typo'd `adopt = "delcared"` quietly
/// meaning `auto` would share probes the operator did not mean to share, so it
/// is a `400`, never a silent default.
///
/// `pub(crate)` for the same reason [`valid_tags`] is: the browser's `PATCH`
/// must accept exactly the labels the enrollment paths accept.
#[allow(clippy::result_large_err)]
pub(crate) fn parse_adopt(
    adopt: Option<&str>,
    default: AdoptPolicy,
) -> Result<AdoptPolicy, Response> {
    match adopt {
        None => Ok(default),
        Some(label) => AdoptPolicy::from_label(label)
            .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "invalid_request")),
    }
}

/// The informational page `verification_uri` points at.
///
/// **Reflects nothing.** No query parameter, no path parameter, no echo of a
/// code: the moment this page renders caller-supplied input it becomes an
/// injection and confused-deputy surface, and it is served unauthenticated to
/// anyone who can reach the coordinator. That is also why the code is not in
/// the URL at all.
const NODE_APPROVE_PAGE: &str = concat!(
    "<!doctype html>\n",
    "<html lang=\"en\">\n",
    "<head><meta charset=\"utf-8\"><title>Approve a node</title></head>\n",
    "<body>\n",
    "<h1>Approve a machine joining your fleet</h1>\n",
    "<p>A machine has asked to join a fleet org as a node, and printed a short\n",
    "code on its own terminal. Approving happens from a machine where you are\n",
    "already logged in:</p>\n",
    "<pre>probe-rs-fleet node approve &lt;your code&gt;</pre>\n",
    "<p>It will show you the machine&#39;s requested name, tags and source\n",
    "address, and ask you to confirm. Approve only if you started that\n",
    "enrollment: approving grants the machine access to hardware in your org,\n",
    "and you cannot see it from here.</p>\n",
    "<p>Not logged in yet?</p>\n",
    "<pre>probe-rs-fleet login</pre>\n",
    "<p>Or approve it in the web UI: <a href=\"/ui/approve\">/ui/approve</a></p>\n",
    "<p>This page is informational: nothing you do here approves anything.</p>\n",
    "</body>\n</html>\n",
);

/// `GET /node/approve` — the static page. Unauthenticated, no state change,
/// byte-identical whatever the query string.
async fn node_approve_page() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        NODE_APPROVE_PAGE,
    )
        .into_response()
}

/// Map a forgs service error onto the one rejection shape.
fn api_err(e: &forgs_http::ApiError) -> Response {
    reject(e.status(), e.code())
}

/// `POST /node/register/start` — begin an approval-pending node registration.
///
/// Necessarily unauthenticated; everything in the body is attacker-controlled
/// and validated before it is stored (it is rendered to a human approver).
/// The source address is advisory and never read from `X-Forwarded-For`.
async fn node_register_start(
    State(coord): State<Arc<Coordinator>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    JsonBody(request): JsonBody<NodeRegisterStartRequest>,
) -> Response {
    let node_name = request.node_name.trim();
    if !valid_node_name(node_name) || !valid_tags(&request.tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Default `auto`: a human is standing over this enrollment.
    let adopt = match parse_adopt(request.adopt.as_deref(), AdoptPolicy::Auto) {
        Ok(adopt) => adopt,
        Err(response) => return response,
    };
    let mut tags = request.tags;
    tags.sort_unstable();
    tags.dedup();
    let payload = PendingNodePayload {
        node_name: node_name.to_owned(),
        tags,
        adopt: adopt.as_str().to_owned(),
    };
    let Ok(payload) = serde_json::to_string(&payload) else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let source_ip = peer.map(|Extension(ConnectInfo(addr))| addr.ip().to_string());
    let started = match forgs_http::device::start_pending_approval(
        coord.auth(),
        &payload,
        source_ip.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return api_err(&e),
    };
    info!(
        node_name,
        source_ip = source_ip.as_deref().unwrap_or("(unknown)"),
        "node registration awaiting approval"
    );
    Json(NodeRegisterStartResponse {
        user_code: started.user_code,
        device_secret: started.device_secret,
        // No code in the URL, ever: the page reflects nothing.
        verification_uri: format!(
            "{}/node/approve",
            coord.config().public_url.trim_end_matches('/')
        ),
        interval: started.interval,
        expires_in: started.expires_in,
    })
    .into_response()
}

/// `POST /node/register/poll` — redeem an approved registration.
///
/// Outcomes describe the caller's own pending registration and are named:
/// `authorization_pending` / `slow_down` / `access_denied` / `expired_token`
/// (all `401`), else the node token.
async fn node_register_poll(
    State(coord): State<Arc<Coordinator>>,
    JsonBody(request): JsonBody<NodeRegisterPollRequest>,
) -> Response {
    use forgs::api::DevicePollResponse as P;
    match forgs_http::device::poll(coord.auth(), &request.device_secret).await {
        Ok(forgs_http::device::PollOutcome::App(v)) => Json(v).into_response(),
        Ok(forgs_http::device::PollOutcome::Login(r)) => match r {
            P::Pending => reject(StatusCode::UNAUTHORIZED, "authorization_pending"),
            P::SlowDown => reject(StatusCode::UNAUTHORIZED, "slow_down"),
            P::Denied => reject(StatusCode::UNAUTHORIZED, "access_denied"),
            P::Expired => reject(StatusCode::UNAUTHORIZED, "expired_token"),
            // A CLI-login secret presented here: not a node registration.
            P::Granted(_) => reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
        },
        Err(e) => api_err(&e),
    }
}

/// `POST /node/register/approve` — inspect, approve or deny a pending
/// registration, as a user session, into `request.org` (default personal).
async fn node_register_approve(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    JsonBody(request): JsonBody<NodeApprovalRequest>,
) -> Response {
    let caller = match authenticate(
        &coord,
        &headers,
        "/node/register/approve",
        &[TokenKind::Session],
        Carrier::Header,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let subject = match acting_subject(&coord, &caller, request.org.as_deref()).await {
        Ok(s) => s,
        Err(r) => {
            audit_denied(&coord, &caller, "node.approve.denied").await;
            return r;
        }
    };
    decide_pending_node(
        &coord,
        &subject,
        &request.user_code,
        request.decision,
        request.replace,
    )
    .await
}

/// Log a refused org claim (there is no org to scope an audit row to).
pub(crate) async fn audit_denied(coord: &Coordinator, caller: &Caller, action: &str) {
    coord
        .auth()
        .audit()
        .record(
            forgs_http::AuditEvent::new(coord.now(), action)
                .subject(caller.subject.key())
                .detail("not a member of the requested org"),
        )
        .await;
}

/// Decide a pending registration for an already-resolved subject (acting org
/// checked). Shared by the CLI route and `POST /api/v1/nodes/pending/{code}`,
/// so the two surfaces cannot drift on who may approve or on the takeover
/// guard.
#[allow(clippy::too_many_lines)]
pub(crate) async fn decide_pending_node(
    coord: &Coordinator,
    subject: &Subject,
    raw_code: &str,
    decision: NodeApprovalDecision,
    replace: bool,
) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
    let (Some(org), Some(user)) = (subject.org().cloned(), subject.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let Some(ns) = crate::subject::ns_of(&org) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    // Unknown / malformed / expired / already-decided: one answer.
    let Some(code) = forgs::user_code::normalise(raw_code) else {
        return reject(StatusCode::NOT_FOUND, "invalid_grant");
    };
    let row = match coord.db().forgs().pending_device_by_code(&code, now).await {
        Ok(Some(row)) => row,
        Ok(None) => return reject(StatusCode::NOT_FOUND, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to look up a pending node registration");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    // A CLI-login row is not a node registration: indistinguishable from
    // unknown here.
    let Some(pending) = PendingNodePayload::of(&row) else {
        return reject(StatusCode::NOT_FOUND, "invalid_grant");
    };
    let collides_with = match coord
        .db()
        .node_id_in_org_by_name(&org, &pending.node_name)
        .await
    {
        Ok(existing) => existing,
        Err(e) => {
            warn!(error = %e, "failed to check for a node-name collision");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let state_label = |row: &forgs_store::PendingDevice| {
        if row.is_denied() {
            "denied"
        } else if row.approved_at.is_some() {
            "approved"
        } else {
            "pending"
        }
    };
    // `org` is the **approver's** target org on every decision, including
    // `Inspect`: "which org am I granting hardware access in?" is answered
    // before the confirmation.
    let describe = |state: &str| NodeApprovalResponse {
        user_code: forgs::user_code::display(&code),
        node_name: pending.node_name.clone(),
        tags: pending.tags.clone(),
        adopt: pending.adopt.clone(),
        source_ip: row.source_ip.clone(),
        created_at: i64::try_from(row.created_at).unwrap_or(i64::MAX),
        expires: i64::try_from(row.expires).unwrap_or(i64::MAX),
        org: Some(org.0.clone()),
        state: state.to_owned(),
        collides_with: collides_with.clone(),
    };
    let user_key = crate::subject::user_key(user).to_string();
    let (action, detail) = match decision {
        NodeApprovalDecision::Inspect => (
            "node.approve.inspect",
            format!("code={code} name={}", pending.node_name),
        ),
        NodeApprovalDecision::Approve => {
            if !row.is_pending() {
                return reject(StatusCode::NOT_FOUND, "invalid_grant");
            }
            // The takeover guard lives here, in the handler: the machine
            // chose its name before any org existed.
            if let Some(existing) = &collides_with {
                if !replace {
                    warn!(org = %org, node = %existing, "refusing an approval that would take over an existing node");
                    return reject(StatusCode::CONFLICT, "node_name_taken");
                }
            }
            match forgs_http::device::decide(coord.auth(), user, &code, Some(ns), true).await {
                Ok(()) => {}
                Err(forgs_http::ApiError::Forbidden) => {
                    return reject(StatusCode::FORBIDDEN, "forbidden")
                }
                Err(e) if e.status() == StatusCode::INTERNAL_SERVER_ERROR => return api_err(&e),
                Err(_) => return reject(StatusCode::NOT_FOUND, "invalid_grant"),
            }
            (
                "node.approve",
                format!(
                    "code={code} name={} adopt={}{}",
                    pending.node_name,
                    pending.adopt,
                    collides_with
                        .as_deref()
                        .map_or_else(String::new, |n| format!(" replaced={n}"))
                ),
            )
        }
        NodeApprovalDecision::Deny => {
            match forgs_http::device::decide(coord.auth(), user, &code, None, false).await {
                Ok(()) => {}
                Err(e) if e.status() == StatusCode::INTERNAL_SERVER_ERROR => return api_err(&e),
                Err(_) => return reject(StatusCode::NOT_FOUND, "invalid_grant"),
            }
            (
                "node.approve.deny",
                format!("code={code} name={}", pending.node_name),
            )
        }
    };
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now_i64,
            subject: Some(&user_key),
            action,
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(org = %org, subject = %user_key, action, "pending node registration decided");
    let state = match decision {
        NodeApprovalDecision::Approve => "approved",
        NodeApprovalDecision::Deny => "denied",
        NodeApprovalDecision::Inspect => state_label(&row),
    };
    Json(describe(state)).into_response()
}

/// `POST /node/enroll` — redeem a `node`-purpose API key for a node token.
///
/// The key's namespace is the org the node joins and its payload the tags
/// stamped onto it; the enrolling machine chooses neither. Such a node has no
/// owning human and the conservative `declared` adoption policy.
async fn node_enroll(
    State(coord): State<Arc<Coordinator>>,
    JsonBody(request): JsonBody<NodeEnrollRequest>,
) -> Response {
    let now = coord.now();
    let ctx = coord.auth();
    let node_name = request.node_name.trim();
    if !valid_node_name(node_name) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Shape / kind / expiry pre-check, before any write.
    let hash = match forgs::verify::verify_api_key(
        ctx.format(),
        ctx.store(),
        &request.auth_key,
        now,
    )
    .await
    {
        Ok((hash, _)) => hash,
        Err(e) => {
            warn!(reason = e.label(), "node enrollment key rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };
    // Purpose checked before the consume, so a mis-typed redemption does not
    // burn a single-use key.
    match ctx.store().api_key_by_hash(&hash).await {
        Ok(Some(meta)) if meta.purpose == PURPOSE_NODE => {}
        Ok(Some(meta)) => {
            warn!(key = %hash.short(), purpose = %meta.purpose, "not a node key");
            return reject(StatusCode::FORBIDDEN, "forbidden");
        }
        Ok(None) => return reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to read an API key");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }
    // The single atomic consume is what makes "single use" true.
    let consumed = match ctx.store().consume_api_key(&hash, now).await {
        Ok(Some(c)) => c,
        Ok(None) => return reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to consume an API key");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let Some(tags) = consumed
        .payload
        .as_deref()
        .map_or(Some(NodeKeyPayload::default()), |p| {
            serde_json::from_str(p).ok()
        })
        .map(|p: NodeKeyPayload| p.tags)
        .filter(|t| valid_tags(t))
    else {
        warn!(key = %hash.short(), "a node key's payload is unusable");
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let org = crate::subject::org_of(consumed.ns);
    let detail = format!("api key {} redeemed", hash.short());
    match coord
        .register_node_and_mint(
            &org,
            node_name,
            &tags,
            None,
            AdoptPolicy::Declared,
            "node.enroll",
            &detail,
        )
        .await
    {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to register node");
            reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// `POST /node/self-register` — register the calling machine as a node of
/// an org the session user is a member of (`probe-rs-fleet share`).
///
/// **Self-approving: membership is sufficient**, and checked. The audit
/// subject is the user, whose authority created the node.
async fn node_self_register(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    JsonBody(request): JsonBody<SelfRegisterRequest>,
) -> Response {
    let caller = match authenticate(
        &coord,
        &headers,
        "/node/self-register",
        &[TokenKind::Session],
        Carrier::Header,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let node_name = request.node_name.trim();
    if !valid_node_name(node_name) || !valid_tags(&request.tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // `share` is a deliberate "offer this machine's probes": default `auto`.
    let adopt = match parse_adopt(request.adopt.as_deref(), AdoptPolicy::Auto) {
        Ok(adopt) => adopt,
        Err(response) => return response,
    };
    let subject = match acting_subject(&coord, &caller, request.org.as_deref()).await {
        Ok(s) => s,
        Err(r) => {
            audit_denied(&coord, &caller, "node.self_register.denied").await;
            return r;
        }
    };
    let (Some(org), Some(user)) = (subject.org().cloned(), subject.user_id()) else {
        return reject(StatusCode::FORBIDDEN, "forbidden");
    };
    let mut tags = request.tags;
    tags.sort_unstable();
    tags.dedup();
    let detail = format!("self-registered by {} (adopt={adopt})", subject.key());
    match coord
        .register_node_and_mint(
            &org,
            node_name,
            &tags,
            Some(user),
            adopt,
            "node.self_register",
            &detail,
        )
        .await
    {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to register node");
            reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_extraction_is_scheme_insensitive_and_trims() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer  prfn1_abc "),
        );
        assert_eq!(bearer_of(&headers), Some("prfn1_abc"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwdw=="),
        );
        assert_eq!(bearer_of(&headers), None);
    }

    #[test]
    fn node_names_and_tags_are_charset_validated() {
        assert!(valid_node_name("rpi-1.lab_2"));
        for bad in ["", "a b", "a/b", "\x1b[2J", &"x".repeat(65)] {
            assert!(!valid_node_name(bad), "{bad:?}");
        }
        assert!(valid_tags(&["nrf52".to_owned()]));
        assert!(!valid_tags(&["a\nb".to_owned()]));
    }
}
