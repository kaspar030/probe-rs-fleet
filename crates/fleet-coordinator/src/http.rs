//! The HTTP/`WebSocket` surface (architecture §3.5).
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /healthz` | anyone | liveness, for the proxy |
//! | `GET /agent` | nodes | `WebSocket` upgrade → the agent control plane |
//! | `GET /client` | users, workloads | `WebSocket` upgrade → the sidecar/ctl plane |
//! | `GET /delegate` | a sandboxed agent | `WebSocket` upgrade → a **crippled** relay-only plane |
//! | `POST /auth/token` | node enrollment, session refresh | JSON token exchange |
//! | `POST /auth/keys` | org members | mint / list / revoke the org's auth keys |
//! | `POST /auth/device/start` | anyone | begin a GitHub device flow |
//! | `POST /auth/device/poll` | anyone | redeem a device code for a session token |
//! | `POST /node/register/start` | anyone | begin an approval-pending node registration |
//! | `POST /node/register/poll` | a pending node | redeem an approved registration for a node token |
//! | `POST /node/register/approve` | org members | inspect / approve / deny one |
//! | `GET /node/approve` | anyone | a static page saying what to run |
//! | `GET /auth/github/start` | anyone | 302 to GitHub's authorize endpoint (browser login) |
//! | `GET /auth/github/callback` | anyone with a valid `state` | exchange the code, set the session cookies |
//! | `GET /api/v1/*` | browser sessions, or a bearer | the read-only JSON API ([`crate::api`]) |
//! | `POST`/`PATCH`/`DELETE /api/v1/*` | browser sessions (+ `X-Fleet-Csrf`), or a bearer | the management verbs ([`crate::api`]) |
//! | `GET /` , `GET /ui` | anyone | `302` to `/ui/` |
//! | `GET /ui/` and each client-side route | anyone | the UI shell ([`crate::assets`]) |
//! | `GET /ui/a/{hash}/*` | anyone | an embedded, immutably-cacheable asset |
//!
//! `/auth/github/*`, `/api/v1/*` and `/ui*` are the browser surface
//! (`docs/web-ui.md`) — named by prefix rather than by position, so the next row
//! anyone adds does not silently make this sentence wrong. Their handlers live
//! in [`crate::browser_auth`], [`crate::api`] and [`crate::assets`] and are
//! merged into the router here. `/api/v1/*` is the **only** prefix on which a
//! cookie is an accepted credential — see [`Carrier`]; the asset routes
//! authenticate nothing at all, because the shell has to load before a session
//! exists.
//!
//! **This router has no global fallback and must not grow one.** Every
//! catch-all is scoped under `/ui/`, which is what makes "the SPA shell cannot
//! swallow `/api/*`, `/agent`, `/client`, `/delegate` or `/healthz`" a property
//! of the router's shape rather than of a test that samples it. See
//! [`crate::assets`].
//!
//! # Interactive node approval (architecture §4.2 rung 3, §6.4)
//!
//! A headless machine with no credential posts to `/node/register/start`,
//! prints the short `user_code` it gets back, and polls `/node/register/poll`.
//! A human on a machine where they are logged in runs `probe-rs-fleet node
//! approve ABCD-1234`, which inspects, confirms, and approves — binding the
//! pending row to *their* org and user. The next poll mints a node token
//! through the same path `self_register` uses.
//!
//! **Why the approval is a CLI verb and not a web form.** `login` is the GitHub
//! *device* flow: deliberately no `redirect_uri`, no cookie session (§6.4). A
//! page served here therefore cannot know who is looking at it, so approving
//! from a browser would mean adding an OAuth redirect flow and cookies to the
//! coordinator. That was the right answer for a coordinator with no web UI, and
//! this paragraph used to end "please do not 'fix' it by bolting a session onto
//! the coordinator".
//!
//! **`docs/web-ui.md` D1 reverses that**, and the reversal is stated here
//! rather than left as a silent contradiction. The coordinator now has an
//! OAuth authorization-code flow and a cookie session, because a web UI needs a
//! browser identity and there is no third option. What it costs is exactly what
//! the old paragraph named:
//!
//! * **one per-deployment setup step** — registering
//!   `<public_url>/auth/github/callback` in the OAuth app, which the device
//!   flow did not need. `[github]` stays optional and a deployment that skips
//!   the registration falls back to the device flow, so it is a nicety rather
//!   than a new requirement (see [`crate::browser_auth::login_method`]);
//! * **a callback origin to get right.** `redirect_uri` is derived from
//!   `public_url`, never from `Host` or `X-Forwarded-Host`: behind a reverse
//!   proxy the coordinator does not see its own public name, and a
//!   Host-derived callback is an attacker-chosen OAuth redirect, i.e. an
//!   account takeover;
//! * **an ambient credential, and therefore CSRF machinery.** A cookie is
//!   attached by the browser to every request to this origin, so the
//!   double-submit token and the mandatory `X-Fleet-Csrf` header exist to
//!   distinguish a call the page made from one another site made on its
//!   behalf. That machinery is the price of `HttpOnly`, which is the price of
//!   not handing a hardware-controlling credential to JavaScript.
//!
//! The blast radius is fenced: cookie authentication is accepted on
//! `/api/v1/*` and **nowhere else** — not `/agent`, `/client` or `/delegate`
//! (a browser must never drive a control-plane `WebSocket` by ambient
//! authority), and not `/auth/token` or `/auth/keys`, which keep requiring an
//! explicit bearer. [`Carrier`] is that fence, and `tests/browser_auth.rs`
//! asserts each of those five routes refuses a cookie-only request.
//!
//! `GET /node/approve` is **still** informational, and stays that way. Phase 1b
//! of `docs/web-ui.md` shipped browser approval — but through
//! `POST /api/v1/nodes/pending/{code}` ([`crate::api`]), not by growing this
//! page a form. Please do not "fix" that: the page's *unauthenticated*
//! rendering must stay byte-identical whatever the query string, which is what
//! makes it reflect nothing, and it is the URL every deployed agent prints.
//!
//! Phase 2 (the UI itself) added **one static paragraph** linking to
//! `/ui/approve`, where the same JSON endpoint is driven from a real form. That
//! is the whole change: no query parameter is read, nothing is echoed, and the
//! rendering is still byte-identical whatever the query string, so
//! `tests/node_approval.rs`'s reflection test keeps holding. A link is the
//! largest thing this page can grow without becoming the form it must not be.
//!
//! The design kept a real browser flow open, and these three properties were
//! commitments rather than accidents. Phase 1b cashed in the first, exactly as
//! written — [`crate::api`]'s handler resolves its subject from the session
//! cookie and calls this file's [`decide_pending_node`] **unchanged**, and
//! shares [`require_membership_to_approve`] with the CLI route so the two
//! surfaces cannot drift on who may approve or on what the audit log says:
//!
//! 1. approval is keyed by `user_code` and is a pure function of `(code,
//!    decision, authenticated user)` — [`decide_pending_node`] takes an
//!    already-resolved subject, so a cookie-authenticated handler resolves its
//!    subject its own way and calls the *same* function. No schema change, no
//!    second binding site;
//! 2. the node-side wire contract (`start` / `poll`) never learns which
//!    approval mechanism ran, so adding one was additive on the coordinator and
//!    already-deployed agents keep working;
//! 3. `GET /node/approve` is what `verification_uri` points at, and the printed
//!    URL did not have to change — which is why it could stay reflection-free
//!    instead of becoming the form.
//!
//! Three accepted risks, recorded rather than fixed:
//!
//! * **Code enumeration across tenants.** An authenticated member who guesses a
//!   `user_code` can approve a registration someone in another org started,
//!   capturing that machine into the approver's org — and can learn its
//!   `node_name` / tags / source IP by `Inspect` alone. What bounds it: ~40 bits
//!   of entropy behind a 15-minute TTL (blind enumeration is infeasible even
//!   unthrottled), every attempt audited, and the enrolling machine printing
//!   the org it landed in, which is the one control that lets the *victim*
//!   notice rather than only an auditor afterwards.
//! * **Unauthenticated database growth.** This is **not** the device flow's
//!   accepted risk and must not be folded into it: the device flow is
//!   *stateless*, while `/node/register/start` writes a row holding
//!   attacker-controlled strings. `max_pending_nodes` (default 256) caps the
//!   live set and the sweep reclaims it at TTL; there is no per-source
//!   throttle. The honest cost of the cap is that a full table denies
//!   enrollment to legitimate machines until rows age out.
//! * **Remote phishing** (RFC 8628 §5.4), sharper here than for login: the
//!   approver grants hardware access in their org to a machine they cannot see.
//!   Mitigated by the CLI showing name, tags, policy, source IP and age, and
//!   requiring an explicit confirmation that defaults to no.
//!
//! `slow_down` is never returned by `/node/register/poll` — there is no rate
//! limiting anywhere in the coordinator — but the CLI handles the code if it
//! ever appears.
//!
//! # The device routes
//!
//! The coordinator **brokers** the GitHub device flow: the CLI never talks to
//! GitHub. The OAuth app's client id/secret stay server-side, the user's GitHub
//! access token never leaves this process (only a fleet session token goes
//! back), and a self-hosted deployment can point at its own OAuth app without
//! anyone rebuilding the CLI.
//!
//! Brokering is **stateless** — there is no `device_flow` table. `/start`
//! returns GitHub's `device_code` verbatim and `/poll` hands it back, so a
//! coordinator restart mid-login is survivable and there is no expiry sweep to
//! write. The device code is exactly the credential a device-flow client is
//! meant to hold, and it is only redeemable with our `client_id`.
//!
//! With no `[github]` table configured both routes answer `503` with the named
//! code `device_flow_unconfigured`. That is deliberately *not* a 404 and not
//! silence: the "no route that 501s" rule above is about responses that are
//! indistinguishable from broken, and a named code the CLI turns into "this
//! coordinator has no GitHub app configured — ask the operator, or use
//! `coordinator user-token`" is the opposite of that.
//!
//! Two accepted risks, recorded rather than fixed (there is no rate limiting
//! anywhere in the coordinator today):
//!
//! * **Quota exhaustion.** `/auth/device/start` must be unauthenticated, so anyone
//!   who can reach it can burn the OAuth app's device-code rate limit and block
//!   logins. No credential is exposed. Acceptable for v1.
//! * **Device-flow remote phishing** (RFC 8628 §5.4). An attacker starts a flow,
//!   gets the `device_code`, and social-engineers a victim into typing the
//!   `user_code`; the attacker's poll then returns a session token *as the
//!   victim*. This is inherent to every device flow, not something the
//!   statelessness above introduces. Documented in architecture §6.4.
//!
//! Poll outcomes keep the no-oracle discipline in the shape that fits: GitHub's
//! `authorization_pending` / `slow_down` / `expired_token` / `access_denied` are
//! relayed verbatim, because they describe the state of *our own* device code
//! (which the caller supplied) rather than answering a question about somebody
//! else's credential. Anything else collapses to `invalid_grant`.
//!
//! # Where a `Subject` comes from
//!
//! [`authenticate_request`] is **the only place a `Subject` is constructed from
//! wire input.** Everything downstream — every authorization check in
//! [`crate::core`] and [`crate::authz`] — consumes the result and is unchanged
//! by how the caller proved itself. Bearer tokens replaced mTLS certificates by
//! replacing this function's *body*, not its shape.
//!
//! `fleet-auth` deliberately stops at [`fleet_auth::Authenticated`] (org, kind,
//! id) and does not mint `Subject`s: it knows nothing about orgs or membership,
//! and a second minting site in a crate with no membership knowledge is exactly
//! how tenancy holes appear.
//!
//! ## One extra carrier, not a second credential
//!
//! The browser surface did **not** get a parallel cookie-authenticating
//! function. [`authenticate_request_with`] takes a [`Carrier`] and, under
//! [`Carrier::HeaderOrCookie`], reads the same credential out of the
//! `prfs_session` cookie when there is no `Authorization` header: the same
//! `prfs1_` token, byte for byte, resolved by the same
//! [`fleet_auth::authenticate`], mapped to the same `Subject`, rejected and
//! audited the same way. `authenticate_request` is now the
//! [`Carrier::Header`] wrapper, so every pre-existing call site is unchanged.
//!
//! What the carrier *does* change is what the caller must additionally prove:
//! a credential that arrived by cookie is ambient, so any mutating call
//! carrying one must also carry `X-Fleet-Csrf`
//! ([`crate::browser_auth::csrf_ok`]). That is why the function reports an
//! [`Arrival`] rather than swallowing the distinction.
//!
//! ## `GET /delegate` constructs none, by design
//!
//! The one route that does not go through [`authenticate_request`], and the
//! reason is architectural rather than convenient: delegating a board to a
//! sandboxed agent (§6.5) must create **no principal**. The sandbox presents a
//! hex-encoded **capability token** as its bearer; [`delegate_ws`] verifies the
//! ed25519 signature with the coordinator's own key, checks expiry, and hands
//! the decoded token to a relay-only loop with a flat message allowlist
//! ([`crate::server::handle_delegate`]). No `Subject` is minted, so there is no
//! identity to escalate, to enumerate the fleet with, or to leave behind when
//! the lease ends.
//!
//! `authenticate_request` could not serve this route even if we wanted it to:
//! it only knows `prfn1_`/`prfs1_` opaque tokens, and its entire output is a
//! `Subject`. The two credential types are kept apart in both directions — a
//! capability token offered on `/client` is rejected, and a session token
//! offered on `/delegate` is too, both with the same flat `401`.
//!
//! # Auditing rejections without an oracle
//!
//! Two rules pull against each other and are resolved deliberately:
//!
//! 1. **Responses are uniform.** A caller learns that its credential did not
//!    work, never why. No "unknown token" vs. "expired token" oracle.
//! 2. **The coordinator's own records are precise.** The reason lands in the
//!    audit log or, when there is no org to scope an audit row to, in a
//!    `tracing` warning carrying the token *kind* and *hash prefix* — never the
//!    token.
//!
//! Why not simply audit everything? `audit_log.org_id` is `NOT NULL REFERENCES
//! org(id)` and the table is reachable only through [`crate::state::OrgDb`].
//! That combination is the mechanism that makes "no code path can forget the org
//! check" true. An unauthenticated rejection has no resolvable org, so auditing
//! it would mean relaxing that column to nullable — inverting a tenant-isolation
//! property for the sake of a diagnostic. It stays `NOT NULL`; pre-auth noise is
//! logged, not audited. **Please do not "fix" this.**

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ws::WebSocketUpgrade, ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use tracing::{debug, info, warn};

use fleet_auth::api::{
    AuthKeyCreated, AuthKeyInfo, AuthKeyList, AuthKeyRequest, AuthKeyRevoked, DevicePollRequest,
    DeviceStartRequest, DeviceStartResponse, ErrorResponse, NodeApprovalDecision,
    NodeApprovalRequest, NodeApprovalResponse, NodeRegisterPollRequest, NodeRegisterStartRequest,
    NodeRegisterStartResponse, TokenRequest, TokenResponse,
};
use fleet_auth::github::{self, DevicePoll, GithubApp, GithubEndpoints};
use fleet_auth::{AuthError, Authenticated, OpaqueToken, TokenKind};
use fleet_proto::adopt::AdoptPolicy;
use fleet_proto::ids::{AgentId, OrgId, Role, Subject, SubjectKind};

use crate::core::Coordinator;
use crate::state::AuditEntry;

/// Build the coordinator's router.
pub fn router(coord: Arc<Coordinator>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/agent", get(agent_ws))
        .route("/client", get(client_ws))
        .route("/delegate", get(delegate_ws))
        .route("/auth/token", post(auth_token))
        .route("/auth/keys", post(auth_keys))
        .route("/auth/device/start", post(auth_device_start))
        .route("/auth/device/poll", post(auth_device_poll))
        .route("/node/register/start", post(node_register_start))
        .route("/node/register/poll", post(node_register_poll))
        .route("/node/register/approve", post(node_register_approve))
        .route("/node/approve", get(node_approve_page))
        // The browser surfaces (`docs/web-ui.md`). Kept in their own modules
        // and merged here rather than listed above, so this file does not grow
        // by ~1500 lines and so the `/api/v1` prefix — the only place a cookie
        // is an accepted credential — stays greppable in one place.
        .merge(crate::browser_auth::github_router())
        .merge(crate::api::router())
        // The UI itself: `/`, `/ui`, the client-side routes and the hashed
        // asset URLs. No `.fallback()` — see the module documentation.
        .merge(crate::assets::router())
        .with_state(coord)
}

/// Liveness probe. Deliberately unauthenticated and content-free.
async fn healthz() -> &'static str {
    "ok"
}

/// The single generic rejection body.
///
/// One shape for every authentication failure, so the response cannot be used to
/// enumerate valid credentials or distinguish expiry from revocation.
///
/// `pub(crate)` so [`crate::api`] and [`crate::browser_auth`] produce the same
/// bodies: two rejection shapes on one coordinator is how a caller learns which
/// module answered it.
pub(crate) fn reject(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: code.to_owned(),
        }),
    )
        .into_response()
}

/// Extract the bearer credential from an `Authorization` header.
fn bearer_of(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(credential.trim())
}

/// Which carriers a route accepts the credential in.
///
/// Not a second credential *kind*: both variants resolve **byte-for-byte the
/// same** `prfs1_` session token through the same [`fleet_auth::authenticate`].
/// The distinction exists because an ambient credential (a cookie the browser
/// attaches to every request to this origin) is forgeable cross-site in a way
/// an explicit header is not, so it needs the CSRF check
/// ([`crate::browser_auth::csrf_ok`]) and it needs to be confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    /// `Authorization: Bearer` only. Every pre-existing route.
    Header,
    /// A bearer header, or the `prfs_session` cookie. **`/api/v1/*` only** —
    /// that allowlist is the blast radius of the whole cookie design
    /// (`docs/web-ui.md` D1), and `tests/browser_auth.rs` asserts each of
    /// `/agent`, `/client`, `/delegate`, `/auth/token`, `/auth/keys` refuses a
    /// cookie-only request.
    HeaderOrCookie,
}

/// How the credential actually arrived.
///
/// The CSRF check keys off this rather than off [`Carrier`]: a browser page
/// that sends an explicit `Authorization` header needs no CSRF token, because
/// the credential it used is not ambient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// In an `Authorization: Bearer` header.
    Header,
    /// In the `prfs_session` cookie.
    Cookie,
}

/// Authenticate a request and build the caller's [`Subject`].
///
/// **The only place a `Subject` is constructed from wire input.** See the module
/// documentation.
///
/// `allowed` is the set of credential kinds this route accepts; a valid
/// credential of another kind is a 403, not a 401, because the caller's problem
/// is the route rather than the credential.
async fn authenticate_request(
    coord: &Coordinator,
    headers: &HeaderMap,
    allowed: &[TokenKind],
) -> Result<(Authenticated, Subject), Response> {
    authenticate_request_with(coord, headers, allowed, Carrier::Header)
        .await
        .map(|(auth, subject, _)| (auth, subject))
}

/// [`authenticate_request`], with the carrier spelled out and reported back.
///
/// Every pre-existing call site goes through the [`Carrier::Header`] wrapper
/// above and is unchanged; `/api/v1` calls this directly. There is deliberately
/// **no** parallel cookie-authenticating function: a second `Subject` minting
/// site in a file whose module doc promises there is only one is how a tenancy
/// hole gets introduced by someone who never read the promise.
///
/// `allowed`, the rejection shapes, the `reject_authentication` /
/// `audit_reject` behaviour and the `Subject` mapping are all shared — the only
/// thing the carrier changes is where the credential string is read from.
pub(crate) async fn authenticate_request_with(
    coord: &Coordinator,
    headers: &HeaderMap,
    allowed: &[TokenKind],
    carrier: Carrier,
) -> Result<(Authenticated, Subject, Arrival), Response> {
    let now = coord.now();
    // The header wins when both are present. Not arbitrary: an explicit
    // credential is a deliberate act by the caller, while a cookie is attached
    // by the browser, so preferring the header means a page that opts into a
    // bearer never has an ambient credential silently substituted for it.
    let (bearer, arrival) = match bearer_of(headers) {
        Some(bearer) => (bearer, Arrival::Header),
        None if carrier == Carrier::HeaderOrCookie => (
            crate::browser_auth::cookie_value(headers, crate::browser_auth::SESSION_COOKIE)
                .unwrap_or(""),
            Arrival::Cookie,
        ),
        None => ("", Arrival::Header),
    };

    let auth = match fleet_auth::authenticate(coord.db(), bearer, now).await {
        Ok(auth) => auth,
        Err(e) => return Err(reject_authentication(&e)),
    };

    if !allowed.contains(&auth.kind) {
        let e = AuthError::WrongKind { got: auth.kind };
        // This rejection *has* a resolvable org (the credential matched a row),
        // so it is auditable — and worth auditing: a node token offered on the
        // operator plane is not a typo.
        audit_reject(coord, &OrgId(auth.org_id.clone()), &auth.id, &e).await;
        return Err(reject(StatusCode::FORBIDDEN, "forbidden"));
    }

    let org = OrgId(auth.org_id.clone());
    let subject = match auth.kind {
        // A node's org and id both come from the `node` row its token hash
        // matched — never from `config.default_org`. This is what stops a node
        // token from being replayed into another tenant.
        TokenKind::Node => Subject::new(org, SubjectKind::Node, auth.id.clone()),
        TokenKind::Session => Subject::new(org, SubjectKind::User, auth.id.clone()),
        // A workload's "org" is the reserved `gha` namespace (architecture
        // §6.7), not a tenant: it is a member of nothing and reaches boards
        // only through per-repo grants, which `board_access` evaluates against
        // this exact subject key.
        TokenKind::Workload => Subject::new(org, SubjectKind::Workload, auth.id.clone()),
        // `authenticate` never returns these kinds; both are redeemed at a
        // route, never presented as a connection credential.
        TokenKind::AuthKey | TokenKind::NodeDevice => {
            return Err(reject(StatusCode::FORBIDDEN, "forbidden"));
        }
    };
    Ok((auth, subject, arrival))
}

/// Log or audit a failed authentication, then produce the uniform rejection.
///
/// 401 vs. 403 is decided by the *route*, not by the credential: a wrong-kind
/// credential gets a 403 because the caller's problem is the door it knocked on.
/// That distinction leaks nothing — it is a function of the token prefix, which
/// the caller supplied — whereas within each status the body is uniform.
fn reject_authentication(e: &AuthError) -> Response {
    // No org is resolvable for any of these: the credential matched no row (or
    // no row was even looked up). Logged, not audited — see the module docs.
    warn!(reason = e.label(), detail = %e, "rejected an unauthenticated request");
    if let AuthError::Store(detail) = e {
        // A storage failure is our fault, not the caller's; still a 401 to the
        // caller (no oracle), but it must be visible as an operational problem.
        warn!(%detail, "credential store failed during authentication");
    }
    if matches!(e, AuthError::WrongKind { .. }) {
        // An auth key presented as a connection credential lands here: it is
        // redeemed at `POST /auth/token`, never presented on an upgrade.
        return reject(StatusCode::FORBIDDEN, "forbidden");
    }
    reject(StatusCode::UNAUTHORIZED, "unauthorized")
}

/// Audit a rejection that *does* have a resolvable org.
///
/// "Resolvable" means an `org` row exists to hang the row off. That is true for
/// every credential kind including a workload, because migration 0007 creates a
/// real `org` row of kind `system` for the reserved `gha` namespace — which is
/// the whole reason it does, rather than leaving the namespace row-less and
/// scattering "never write here" conditions through the code.
async fn audit_reject(coord: &Coordinator, org: &OrgId, subject_id: &str, e: &AuthError) {
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let detail = e.to_string();
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(subject_id),
            action: e.label(),
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    warn!(org = %org, subject = %subject_id, reason = e.label(), "rejected an authenticated request");
}

/// `GET /agent` — a node's persistent control-plane connection.
async fn agent_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (auth, _subject) = match authenticate_request(&coord, &headers, &[TokenKind::Node]).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let agent_id = AgentId(auth.id.clone());
    let org = OrgId(auth.org_id.clone());
    info!(%agent_id, %org, "agent connected");

    ws.max_message_size(fleet_wire::MAX_FRAME_LEN)
        .max_frame_size(fleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) = crate::server::handle_agent(
                coord,
                Box::new(tx),
                Box::new(rx),
                agent_id.clone(),
                auth,
            )
            .await
            {
                if fleet_wire::is_benign_close(&e.as_wire()) {
                    debug!(%agent_id, "agent connection closed");
                } else {
                    debug!(%agent_id, error = %e, "agent connection closed");
                }
            }
        })
}

/// `GET /client` — a ctl or sidecar connection.
///
/// Accepts a user session **or** a CI workload token (architecture §6.7). The
/// allowlist is the fence that keeps a workload off `/agent` and `/auth/keys`:
/// a CI job must not be able to enroll a node or mint credentials, and
/// `require_role` alone would not say so (a workload has no role anywhere, but
/// relying on that is relying on an absence). The verbs reachable *behind* this
/// route were walked too — see `Coordinator::delegate`, which refuses a
/// workload explicitly.
async fn client_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (_auth, subject) = match authenticate_request(
        &coord,
        &headers,
        &[TokenKind::Session, TokenKind::Workload],
    )
    .await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    debug!(%subject, "client connected");

    ws.max_message_size(fleet_wire::MAX_FRAME_LEN)
        .max_frame_size(fleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) =
                crate::server::handle_sidecar(coord, Box::new(tx), Box::new(rx), subject).await
            {
                // ctl exits immediately after one RPC, so a close here is the
                // normal end of a session, not a transport fault.
                if fleet_wire::is_benign_close(&e.as_wire()) {
                    tracing::trace!("client connection closed by peer");
                } else {
                    debug!(error = %e, "client connection closed");
                }
            }
        })
}

/// `GET /delegate` — a sandboxed agent holding nothing but a capability token.
///
/// The one authenticated route that mints **no [`Subject`]** (see the module
/// docs). The bearer is the hex-encoded wire form of a
/// [`fleet_proto::token::SignedToken`]; the coordinator verifies the signature
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
    use fleet_proto::token::{SignedToken, TokenVerifier as _};

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

    ws.max_message_size(fleet_wire::MAX_FRAME_LEN)
        .max_frame_size(fleet_wire::MAX_FRAME_LEN)
        .on_upgrade(move |socket| async move {
            let (tx, rx) = crate::ws_axum::split(socket);
            if let Err(e) =
                crate::server::handle_delegate(coord, Box::new(tx), Box::new(rx), token).await
            {
                if fleet_wire::is_benign_close(&e.as_wire()) {
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

/// `POST /auth/token` — the JSON token exchange.
async fn auth_token(
    State(coord): State<Arc<Coordinator>>,
    Json(request): Json<TokenRequest>,
) -> Response {
    match request {
        TokenRequest::AuthKey {
            auth_key,
            node_name,
            tags,
        } => redeem_auth_key(&coord, &auth_key, &node_name, tags).await,
        TokenRequest::Refresh { session_token } => refresh_session(&coord, &session_token).await,
        TokenRequest::SelfRegister {
            session_token,
            node_name,
            tags,
            adopt,
        } => self_register(&coord, &session_token, &node_name, tags, adopt.as_deref()).await,
        TokenRequest::GithubOidc { oidc_token } => exchange_github_oidc(&coord, &oidc_token).await,
        TokenRequest::WorkloadKey { auth_key } => exchange_workload_key(&coord, &auth_key).await,
    }
}

/// Redeem an auth key: create/refresh the node row and mint its token.
async fn redeem_auth_key(
    coord: &Coordinator,
    auth_key: &str,
    node_name: &str,
    tags: Vec<String>,
) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    if !valid_node_name(node_name.trim()) || !valid_tags(&tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }

    // Shape/expiry pre-check, so a malformed key is rejected without a write and
    // the reason is nameable in the log.
    let hash = match fleet_auth::verify::verify_auth_key(coord.db(), auth_key, now).await {
        Ok((hash, _record)) => hash,
        Err(e) => {
            warn!(reason = e.label(), "auth key rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    // The single atomic consume is what makes "single use" true under
    // concurrent redemption; the check above is a courtesy, not the guard.
    let Ok(Some((org, key_tags))) = coord.db().consume_auth_key(hash.as_str(), now_i64).await else {
        warn!(key = %hash.short(), "auth key could not be consumed");
        return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
    };

    let token = OpaqueToken::mint(TokenKind::Node);
    let mut all_tags = key_tags;
    all_tags.extend(tags);
    all_tags.sort_unstable();
    all_tags.dedup();

    let node = match coord
        .db()
        .register_node(&org, node_name, token.hash().as_str(), &all_tags, now_i64)
        .await
    {
        Ok(node) => node,
        Err(e) => {
            warn!(error = %e, "failed to register node");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now_i64,
            subject: Some(node.0.as_str()),
            action: "node.enroll",
            node: Some(node.0.as_str()),
            board: None,
            lease: None,
            detail: Some("auth key redeemed"),
        })
        .await;
    info!(node = %node, org = %org, "node enrolled");

    Json(TokenResponse {
        token: token.to_secret_string(),
        node_id: Some(node.0),
        org: org.0,
        // A node belongs to exactly one org, so there is nothing to list here.
        orgs: Vec::new(),
        expires: None,
        coordinator_token_pubkey: Some(coord.token_pubkey_hex()),
        login: None,
    })
    .into_response()
}

/// `grant_type: github_oidc` — exchange a GitHub Actions OIDC JWT for a
/// per-job workload token (architecture §6.7).
///
/// # The trust rule, in one place
///
/// A verified token proves "a job in repo `owner/name` at ref X". Mapping that
/// to fleet hardware takes an **explicit per-repo grant** and nothing else:
/// `repository_owner` is recorded on the row and in the audit detail, and is
/// never consulted. A fork, or a newly created repo under a granted owner,
/// therefore produces a subject key no grant names and is refused with
/// `403 no_grant`. That refusal is the security-relevant behaviour of this
/// whole path; `workload_oidc.rs` pins it with a sibling grant proving the
/// owner *is* otherwise reachable.
///
/// # Failure shapes
///
/// * no `[github_actions]` table → `503 workload_oidc_unconfigured`, mirroring
///   `device_flow_unconfigured` — a named code beats silence;
/// * any verification failure → a flat `401 invalid_grant`, with the reason in
///   the log only (no oracle). An unknown `kid` first triggers **one** JWKS
///   refresh, because that is what a key rotation looks like; the refresh is
///   itself rate-limited so an attacker feeding invented `kid`s cannot turn
///   this route into a fetch amplifier;
/// * a verified token with no grant → `403 no_grant`. Deliberately
///   distinguishable from `401`: the credential *is* valid, and conflating the
///   two would send an operator hunting a signing problem when the answer is
///   "run `grant --repo`". It leaks only that the repo is not granted, which is
///   something the repo's own maintainers already know.
// Long, and deliberately linear: verify, look up the grant, mint, audit, reply.
// Every step's failure has its own named response, and factoring the tail into
// helpers would separate each rejection from the reason it exists.
#[allow(clippy::too_many_lines)]
async fn exchange_github_oidc(coord: &Coordinator, jwt: &str) -> Response {
    use fleet_auth::oidc::{self, OidcError, OidcPolicy};

    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    let (Some(gha), Some(cache)) = (coord.config().github_actions.as_ref(), coord.jwks_cache())
    else {
        debug!("workload OIDC exchange attempted with no [github_actions] table");
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "workload_oidc_unconfigured",
        );
    };
    let policy = OidcPolicy {
        issuer: gha.issuer.clone(),
        audience: gha.audience.clone(),
        leeway_secs: 60,
    };

    let keys = match cache.get().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(reason = e.label(), detail = %e, "JWKS unavailable");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };
    let claims = match oidc::verify(jwt, &keys, &policy, now) {
        Ok(claims) => Ok(claims),
        // The rotation case, and the only error worth a second attempt: the
        // issuer published a new key after our last fetch.
        Err(OidcError::UnknownKid(kid)) => match cache.refresh_for_unknown_kid().await {
            Ok(fresh) => {
                debug!(%kid, "refreshed the JWKS for an unknown key id");
                oidc::verify(jwt, &fresh, &policy, now)
            }
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    let claims = match claims {
        Ok(claims) => claims,
        Err(e) => {
            // The reason is logged, never returned: the body is the same flat
            // `invalid_grant` for expiry, audience, issuer, signature and
            // everything else.
            warn!(reason = e.label(), detail = %e, "workload OIDC token rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    let key = fleet_proto::ids::workload_subject_key(&claims.repository);
    let grants = match coord.db().grants_for_subject(&key, now_i64).await {
        Ok(grants) => grants,
        Err(e) => {
            warn!(error = %e, "grant lookup failed during workload exchange");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    if grants.is_empty() {
        // Named in the log with the repo, because the operator's next action is
        // exactly `grant --repo <that repo>`. The owner is logged beside it so
        // the "but I granted the org!" case is diagnosable in one line.
        warn!(
            repository = %claims.repository,
            repository_owner = %claims.repository_owner,
            "no grant for this repository; the owner is deliberately not sufficient"
        );
        return reject(StatusCode::FORBIDDEN, "no_grant");
    }

    let token = OpaqueToken::mint(TokenKind::Workload);
    let expires = now_i64.saturating_add(
        i64::try_from(gha.workload_token_ttl_secs).unwrap_or(i64::from(i32::MAX)),
    );
    let columns = crate::state::WorkloadClaimColumns {
        repository: Some(claims.repository.clone()),
        repository_owner: Some(claims.repository_owner.clone()),
        git_ref: claims.git_ref.clone(),
        workflow: claims.workflow.clone(),
        job_workflow_ref: claims.job_workflow_ref.clone(),
        run_id: claims.run_id.clone(),
    };
    if let Err(e) = coord
        .db()
        .insert_workload_token(
            token.hash().as_str(),
            &key,
            "github_oidc",
            &columns,
            now_i64,
            expires,
        )
        .await
    {
        warn!(error = %e, "failed to record a workload token");
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }

    // One audit row per granting org: each of them is lending hardware to this
    // job, and each of their operators must be able to answer "who used what,
    // for how long" from their own audit log alone (§6.6's metering note). The
    // `leases` rows carry the duration half.
    let mut orgs: Vec<String> = grants.iter().map(|g| g.org.0.clone()).collect();
    orgs.sort_unstable();
    orgs.dedup();
    let grant_ids: Vec<&str> = grants.iter().map(|g| g.id.as_str()).collect();
    let detail = format!(
        "repo={} owner={} ref={} workflow={} run={} grants=[{}]",
        claims.repository,
        claims.repository_owner,
        claims.git_ref.as_deref().unwrap_or("-"),
        claims.workflow.as_deref().unwrap_or("-"),
        claims.run_id.as_deref().unwrap_or("-"),
        grant_ids.join(","),
    );
    let subject_rendered = key.to_string();
    for org in &orgs {
        let _ = coord
            .db()
            .scoped(OrgId(org.clone()))
            .append_audit(&AuditEntry {
                ts: now_i64,
                subject: Some(subject_rendered.as_str()),
                action: "workload.token.mint",
                node: None,
                board: None,
                lease: None,
                detail: Some(&detail),
            })
            .await;
    }
    info!(
        repository = %claims.repository,
        orgs = %orgs.join(","),
        "minted a workload token"
    );

    Json(TokenResponse {
        token: token.to_secret_string(),
        node_id: None,
        // Not a scope — a workload belongs to no org. The first granting org,
        // so the CLI has something to print; `orgs` is the honest answer.
        org: orgs.first().cloned().unwrap_or_default(),
        orgs,
        expires: Some(u64::try_from(expires).unwrap_or(0)),
        coordinator_token_pubkey: None,
        login: None,
    })
    .into_response()
}

/// `grant_type: workload_key` — redeem a **workload auth key** for a workload
/// token, for a runner with no workload identity of its own (architecture
/// §6.7).
///
/// # This is the weak path, stated plainly
///
/// Everything the OIDC path avoids, this one accepts: a long-lived bearer
/// secret sitting in somebody else's CI configuration, usable by anyone who
/// reads that configuration or a leaked log. It exists because heterogeneous
/// runners are a stated requirement and a self-hosted Jenkins box has no
/// workload identity to offer. What bounds it: the key is org-scoped, tagged
/// (so the synthesised grant selects a subset of boards, never all of them),
/// op-scoped, expiring, listable and revocable — and revoking it tears down the
/// grant, and therefore live leases, rather than waiting out a TTL.
///
/// # Why redemption synthesises a grant rather than widening `board_access`
///
/// An auth key has always minted a **node** token: a machine that offers
/// probes. Teaching `board_access` to honour an auth key directly would
/// silently turn every existing enrollment key in every deployment into a
/// board-access credential. Instead the key carries an explicit
/// `purpose = 'ci'`, and redeeming one upserts an **ordinary grant** to an
/// org-scoped workload subject — the same row `grant --repo` writes, evaluated
/// by the same code, revocable by the same verb.
// Linear for the same reason [`exchange_github_oidc`] is.
#[allow(clippy::too_many_lines)]
async fn exchange_workload_key(coord: &Coordinator, auth_key: &str) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    // Shape/expiry pre-check, so a malformed key is rejected without a write.
    let hash = match fleet_auth::verify::verify_auth_key(coord.db(), auth_key, now).await {
        Ok((hash, _record)) => hash,
        Err(e) => {
            warn!(reason = e.label(), "workload key rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    // A `node` key must not become a board-access credential: that is the whole
    // reason `purpose` exists. Checked before the consume, so a mis-typed
    // redemption does not burn a single-use enrollment key.
    let meta = match coord.db().ci_auth_key_meta(hash.as_str()).await {
        Ok(Some(meta)) => meta,
        Ok(None) => return reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to read an auth key's CI metadata");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    if meta.purpose != crate::state::AUTH_KEY_PURPOSE_CI {
        warn!(
            key = %hash.short(), purpose = %meta.purpose,
            "auth key is not a CI key; refusing to mint a workload token"
        );
        return reject(StatusCode::FORBIDDEN, "forbidden");
    }

    // The single atomic consume, exactly as `redeem_auth_key` does it: a
    // single-use key is spent here and a multi-use one is left redeemable.
    let Ok(Some((org, tags))) = coord.db().consume_auth_key(hash.as_str(), now_i64).await else {
        warn!(key = %hash.short(), "workload key could not be consumed");
        return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
    };
    if tags.is_empty() {
        // Belt to `auth-key create --purpose ci`'s brace: an empty tag set is
        // an *empty selector*, which matches every board in the org. The
        // selector parser refuses one at every other entry point and so does
        // this, rather than synthesising a grant to the whole fleet.
        warn!(key = %hash.short(), "a CI auth key with no tags cannot be redeemed");
        return reject(StatusCode::FORBIDDEN, "forbidden");
    }

    // Subject: org-scoped, so it can never collide with a `gha/workload:` repo
    // subject. Two spellings, and which one applies is the whole of this
    // feature:
    //
    // * **named** (`--as <name>`) — an identity. The subject and the grant id
    //   are functions of `(org, name)`, so re-minting the key rotates the
    //   secret without changing who it speaks as: `upsert_grant` re-upserts the
    //   same row, keeping the audit trail, the concurrency budget and the
    //   revocation handle whole.
    // * **unnamed** — today's behaviour, byte for byte. Derived from the key
    //   hash, so every runner redeeming the same key is the same subject (one
    //   grant row, one concurrency budget) and rotating the key forks the
    //   identity. Migration 0009's NULL means exactly this, so no pre-existing
    //   key changes meaning.
    //
    // The name is re-validated on read. A name only ever enters the column
    // through `normalise_agent_name` at mint time, so a failure here means the
    // row was hand-edited — and constructing a subject id from unvalidated text
    // is precisely what the charset rule exists to prevent.
    let (key_subject, grant_id) = match meta.subject_name.as_deref() {
        Some(raw) => {
            let Some(name) = fleet_proto::ids::normalise_agent_name(raw) else {
                warn!(
                    key = %hash.short(),
                    "auth key carries an invalid identity name; refusing to mint a workload token"
                );
                return reject(StatusCode::FORBIDDEN, "forbidden");
            };
            let subject = fleet_proto::ids::agent_subject_key(&org, &name);
            let id = named_ci_grant_id(&org, &name);
            (subject, id)
        }
        None => (
            fleet_proto::ids::SubjectKey {
                org: org.clone(),
                kind: SubjectKind::Workload,
                id: format!("key:{}", hash.short()),
            },
            // Prefixed `ci-` and therefore in a namespace no human-created
            // grant id can occupy (those are 32 random hex characters), which
            // is what keeps `grant revoke <prefix>` unambiguous between the two.
            format!("ci-{}", hash.as_str().get(..29).unwrap_or(hash.as_str())),
        ),
    };

    let selector = tags
        .iter()
        .map(|t| format!("tag={t}"))
        .collect::<Vec<_>>()
        .join(" && ");
    let selector =
        match fleet_proto::lease::parse_constraint(&selector) {
            Ok(c) => c.to_string(),
            Err(e) => {
                warn!(error = %e, "a CI auth key's tags do not form a valid selector");
                // A *caller* fault, not a coordinator one: the tags came in at
                // mint time (and `auth-key create` can be driven from a shell,
                // which historically skipped `valid_tags`), so a `server_error`
                // here would be a lie that pages someone for a typo. Refuse the
                // redemption the way the tagless-`ci` case above does.
                return reject(StatusCode::FORBIDDEN, "forbidden");
            }
        };
    let ops = if meta.ops.is_empty() {
        DEFAULT_CI_KEY_OPS.to_vec()
    } else {
        fleet_proto::token::normalize_ops(
            meta.ops
                .iter()
                .filter_map(|o| fleet_proto::token::AllowedOp::from_label(o))
                .collect(),
        )
    };

    // A deterministic grant id derived above, so a multi-use key upserts one
    // row however many runners redeem it (and a rotated named key re-upserts
    // the identity's row rather than creating a second one).
    //
    // The grant inherits the key's expiry; a shell-minted perpetual key gets a
    // bounded one rather than an unbounded share of the org's hardware.
    let grant_expires = meta
        .expires
        .unwrap_or_else(|| now_i64.saturating_add(DEFAULT_CI_GRANT_TTL_SECS));

    if let Err(e) = coord
        .db()
        .scoped(org.clone())
        .upsert_grant(
            &grant_id,
            &key_subject,
            &selector,
            &ops,
            Some(grant_expires),
            None,
            now_i64,
        )
        .await
    {
        warn!(error = %e, "failed to synthesise a CI key's grant");
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }

    let token = OpaqueToken::mint(TokenKind::Workload);
    let ttl = coord
        .config()
        .github_actions
        .as_ref()
        .map_or(DEFAULT_WORKLOAD_KEY_TTL_SECS, |g| g.workload_token_ttl_secs);
    // Never outlive the key's own expiry: a key revoked by letting it lapse
    // must not leave a token running past it.
    let expires = now_i64
        .saturating_add(i64::try_from(ttl).unwrap_or(i64::from(i32::MAX)))
        .min(grant_expires);
    if let Err(e) = coord
        .db()
        .insert_workload_token(
            token.hash().as_str(),
            &key_subject,
            "auth_key",
            &crate::state::WorkloadClaimColumns::default(),
            now_i64,
            expires,
        )
        .await
    {
        warn!(error = %e, "failed to record a workload token");
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }

    let subject_rendered = key_subject.to_string();
    // `as=<name>` when named, so the audit trail says which identity the key
    // spoke as — the fact that survives the rotation the name exists for.
    let detail = match meta.subject_name.as_deref() {
        Some(name) => format!(
            "auth key {} as={name} selector={selector} grant={grant_id}",
            hash.short()
        ),
        None => format!(
            "auth key {} selector={selector} grant={grant_id}",
            hash.short()
        ),
    };
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now_i64,
            subject: Some(subject_rendered.as_str()),
            action: "workload.token.mint",
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(org = %org, key = %hash.short(), "minted a workload token from an auth key");

    Json(TokenResponse {
        token: token.to_secret_string(),
        node_id: None,
        org: org.0.clone(),
        orgs: vec![org.0],
        expires: Some(u64::try_from(expires).unwrap_or(0)),
        coordinator_token_pubkey: None,
        login: None,
    })
    .into_response()
}

/// Ops a CI auth key confers when `--ops` was not given.
///
/// `attach` is implied by the data-plane ops anyway (`normalize_ops`), and is
/// listed for readability. `power-cycle` is deliberately absent: an unattended
/// runner cutting power to a lab board should be an explicit choice.
const DEFAULT_CI_KEY_OPS: [fleet_proto::token::AllowedOp; 4] = [
    fleet_proto::token::AllowedOp::Attach,
    fleet_proto::token::AllowedOp::Flash,
    fleet_proto::token::AllowedOp::Reset,
    fleet_proto::token::AllowedOp::Erase,
];

/// The deterministic grant id a **named** CI key's redemption upserts:
/// `ci-` followed by 29 hex characters of `SHA-256(org \n "agent:" name)`.
///
/// The single spelling, shared by the mint/redeem path
/// ([`exchange_workload_key`]) and the revocation cascade
/// ([`revoke_auth_key`]), because a cascade that computed a different id from
/// the same key would silently do nothing.
///
/// # Why the org is mixed into the digest
///
/// `grant.id` is a **global** `PRIMARY KEY` (`0001_init.sql`), not `(org_id, id)`,
/// and `OrgDb::upsert_grant` does `ON CONFLICT(id) DO UPDATE SET selector, ops,
/// expires` without touching `org_id`. So an id derived from the name alone
/// (`ci-name-builder`) would let org B's redemption silently rewrite org A's
/// grant row's selector and ops while leaving it owned by A: a cross-tenant
/// write. Mixing the org in makes that unrepresentable rather than merely
/// unlikely.
///
/// # Why hex, and why the `ci-` prefix
///
/// [`crate::core::Coordinator::grant_revoke_core`] accepts a prefix only if,
/// after stripping an optional `ci-`, the body is at least 8 **hex**
/// characters. `grant list` prints these ids, so a non-hex id would be printed
/// and then refused by its own revoke verb. Staying inside the `ci-` namespace
/// also keeps a synthesised id distinguishable from a human-created one (32
/// random hex with no prefix).
///
/// The cost, stated openly: the id is opaque, so an operator cannot read the
/// name off it in `grant list`. The row's **subject** column — which that
/// listing also prints — renders `<org>/workload:agent:<name>` in clear text,
/// and the mint epilogue prints both. Do not "improve" this into a readable id
/// without re-reading the paragraph above about `grant.id` being global.
///
/// Named ids and unnamed ones (`ci-` + 29 characters of a key hash) now share
/// the `ci-` namespace by construction rather than by accident; a collision
/// between them is a ~116-bit coincidence, and the namespace still excludes
/// human-created ids entirely.
pub(crate) fn named_ci_grant_id(org: &OrgId, name: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(org.0.as_bytes());
    hasher.update(b"\nagent:");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("ci-{}", &hex[..29])
}

/// Bound on the grant synthesised for a key that never expires.
///
/// A shell-minted `--ttl 0` key is an operator's informed choice about the
/// *key*; it is not a choice to share the org's hardware forever, which is the
/// artefact §6.5 refuses to let a grant be.
const DEFAULT_CI_GRANT_TTL_SECS: i64 = 30 * 24 * 3600;

/// Workload-token TTL when there is no `[github_actions]` table.
///
/// The auth-key path works without one — it involves no issuer — so it needs
/// its own default rather than refusing to run.
const DEFAULT_WORKLOAD_KEY_TTL_SECS: u64 = 3600;

/// Self-register the calling machine as a node in the caller's own org
/// (architecture §4.2 path 2, §6.4). This is what `probe-rs-fleet share` calls.
///
/// **Self-approving: membership is sufficient.** There is no admin approval
/// step — a decision, not an omission (§6.4); a device-approval gate can be
/// added later without a data migration.
///
/// Membership *is* checked, though, and that check is not decorative:
/// `authz::require_role` denies a non-member everywhere else, so a node
/// created for one would be an orphan its "owner" could never use.
///
/// The audit row's subject is the **user**, unlike [`redeem_auth_key`] where it
/// is the node. That asymmetry is the point: here a human's authority is what
/// created the node, and that is the fact worth being able to look up later.
async fn self_register(
    coord: &Coordinator,
    session_token: &str,
    node_name: &str,
    tags: Vec<String>,
    adopt: Option<&str>,
) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    // Same validation as the interactive path, which needs it far more (an
    // unauthenticated caller chooses the name there). Applied here too because
    // the name lands inside the node id and a member should not be able to
    // create a node whose name breaks that, even by accident.
    if !valid_node_name(node_name.trim()) || !valid_tags(&tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }

    // An unrecognised policy is a 400, never a silent default: a typo'd
    // `adopt = "delcared"` quietly meaning `auto` would share probes the
    // operator did not mean to share. Absent means this grant's default, which
    // is `auto` — `share` is a deliberate "offer this machine's probes".
    let adopt = match parse_adopt(adopt, AdoptPolicy::Auto) {
        Ok(adopt) => adopt,
        Err(response) => return response,
    };

    let auth = match fleet_auth::authenticate(coord.db(), session_token, now).await {
        Ok(auth) if auth.kind == TokenKind::Session => auth,
        Ok(auth) => {
            let e = AuthError::WrongKind { got: auth.kind };
            audit_reject(coord, &OrgId(auth.org_id.clone()), &auth.id, &e).await;
            return reject(StatusCode::FORBIDDEN, "forbidden");
        }
        Err(e) => {
            warn!(reason = e.label(), "self-registration rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    let org = OrgId(auth.org_id.clone());
    match coord.db().role_of(&org, &auth.id).await {
        Ok(Some(_role)) => {}
        Ok(None) => {
            // Audited with its own action rather than an `AuthError` label: the
            // credential was perfectly valid, so this is an *authorization*
            // refusal. Conflating it with a credential rejection would hide the
            // one case an operator actually needs to see — someone whose
            // membership was revoked still holding a live session.
            let _ = coord
                .db()
                .scoped(org.clone())
                .append_audit(&AuditEntry {
                    ts: now_i64,
                    subject: Some(auth.id.as_str()),
                    action: "node.self_register.denied",
                    node: None,
                    board: None,
                    lease: None,
                    detail: Some("not a member of the org the session belongs to"),
                })
                .await;
            warn!(org = %org, subject = %auth.id, "self-registration by a non-member");
            return reject(StatusCode::FORBIDDEN, "forbidden");
        }
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }

    let mut all_tags = tags;
    all_tags.sort_unstable();
    all_tags.dedup();

    let detail = format!("self-registered by {} (adopt={adopt})", auth.id);
    mint_node_token(
        coord,
        &org,
        node_name,
        &all_tags,
        &auth.id,
        adopt,
        "node.self_register",
        &detail,
        now_i64,
    )
    .await
}

/// Mint a node token, create/refresh the node row, and audit it.
///
/// The shared tail of [`self_register`] and the interactive-approval redemption
/// in [`node_register_poll`], so the two paths cannot drift in what a node row
/// ends up looking like — same owner semantics, same tag handling, same
/// response shape. The audit `action` and `detail` differ because the two
/// ceremonies are genuinely different events; everything else is identical.
///
/// `owner` is the **user** whose authority created the node (the session holder
/// for `share`, the approver for interactive approval), so `node.owner_user_id`
/// means the same thing on both paths.
#[allow(clippy::too_many_arguments)]
async fn mint_node_token(
    coord: &Coordinator,
    org: &OrgId,
    node_name: &str,
    tags: &[String],
    owner: &str,
    adopt: AdoptPolicy,
    audit_action: &'static str,
    audit_detail: &str,
    now: i64,
) -> Response {
    let token = OpaqueToken::mint(TokenKind::Node);
    let node = match coord
        .db()
        .register_node_full(
            org,
            node_name,
            token.hash().as_str(),
            tags,
            Some(owner),
            adopt,
            now,
        )
        .await
    {
        Ok(node) => node,
        Err(e) => {
            warn!(error = %e, "failed to register node");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(owner),
            action: audit_action,
            node: Some(node.0.as_str()),
            board: None,
            lease: None,
            detail: Some(audit_detail),
        })
        .await;
    info!(node = %node, org = %org, owner = %owner, %adopt, action = audit_action, "node registered");

    Json(TokenResponse {
        token: token.to_secret_string(),
        node_id: Some(node.0),
        org: org.0.clone(),
        orgs: Vec::new(),
        expires: None,
        coordinator_token_pubkey: Some(coord.token_pubkey_hex()),
        login: None,
    })
    .into_response()
}

/// Exchange a still-valid session token for a fresh one.
async fn refresh_session(coord: &Coordinator, session_token: &str) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    let auth = match fleet_auth::authenticate(coord.db(), session_token, now).await {
        Ok(auth) if auth.kind == TokenKind::Session => auth,
        Ok(auth) => {
            let e = AuthError::WrongKind { got: auth.kind };
            audit_reject(coord, &OrgId(auth.org_id.clone()), &auth.id, &e).await;
            return reject(StatusCode::FORBIDDEN, "forbidden");
        }
        Err(e) => {
            warn!(reason = e.label(), "session refresh rejected");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    let fresh = OpaqueToken::mint(TokenKind::Session);
    let expires =
        now_i64.saturating_add(i64::try_from(coord.config().session_ttl_secs).unwrap_or(i64::MAX));
    let org = OrgId(auth.org_id.clone());
    if coord
        .db()
        .insert_session(fresh.hash().as_str(), &org, &auth.id, now_i64, expires)
        .await
        .is_err()
    {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    // Refresh replaces: the old token stops working immediately, so a stolen
    // one has a strictly bounded life even if the theft is not noticed.
    let _ = coord.db().delete_session(auth.hash.as_str()).await;

    Json(TokenResponse {
        token: fresh.to_secret_string(),
        node_id: None,
        org: org.0,
        // A session belongs to exactly one org, so there is nothing to list.
        orgs: Vec::new(),
        expires: u64::try_from(expires).ok(),
        coordinator_token_pubkey: None,
        login: None,
    })
    .into_response()
}

/// The longest TTL `POST /auth/keys` will mint (30 days).
///
/// Auth keys are the weak link in the credential model: long-lived bearer
/// secrets that end up in CI config and disk images. A never-expiring key minted
/// from a shell on the coordinator host is an operator's informed choice
/// (`coordinator auth-key --ttl 0` still allows it); a hosted org member's is
/// not, so this path refuses `ttl_secs = 0` and caps the rest. A config knob is
/// a trivial follow-up; a documented constant keeps the config surface flat.
///
/// `pub(crate)` so [`crate::api`] can *report* the bound rather than duplicate
/// it: the browser has to constrain a TTL input, and a frontend that hardcoded
/// `30` would be silently wrong the day this constant moves.
pub(crate) const MAX_API_AUTH_KEY_TTL_SECS: u64 = 30 * 24 * 3600;

/// The shortest revocation prefix `POST /auth/keys` accepts, in hex characters.
///
/// Reported by [`crate::api`] for the same reason as the TTL cap above; the
/// enforcement stays in [`revoke_auth_key`], which is the only place that may
/// decide it.
pub(crate) const MIN_AUTH_KEY_PREFIX_LEN: usize = 8;

/// `POST /auth/keys` — mint, list and revoke the caller's org's auth keys
/// (architecture §6.4).
///
/// This is the hosted counterpart of `coordinator auth-key`: a customer with a
/// `[user]` session and no shell on our host can still enroll a headless node.
///
/// Two properties make it safe to let a plain member mint:
///
/// * **the org comes from the session, never from the request**, so a minted key
///   can never exceed the caller's own org; and
/// * membership is checked, and membership is already sufficient to add a node
///   (§6.4/§6.5) — an auth key adds nothing a member could not do with `share`,
///   except do it on a machine they are not sitting at.
async fn auth_keys(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(request): Json<AuthKeyRequest>,
) -> Response {
    let (auth, subject) = match authenticate_request(&coord, &headers, &[TokenKind::Session]).await {
        Ok(v) => v,
        Err(response) => return response,
    };
    let org = OrgId(auth.org_id.clone());
    let now_i64 = i64::try_from(coord.now()).unwrap_or(i64::MAX);

    if let Err(response) = require_membership_for_auth_keys(&coord, &org, &auth.id, now_i64).await {
        return response;
    }

    match request {
        AuthKeyRequest::Create {
            tags,
            ttl_secs,
            multi_use,
            purpose,
            ops,
            subject_name,
        } => {
            create_auth_key(
                &coord,
                &org,
                &auth.id,
                tags,
                ttl_secs,
                multi_use,
                purpose.as_deref(),
                ops,
                subject_name.as_deref(),
                now_i64,
            )
            .await
        }
        AuthKeyRequest::List {} => list_auth_keys(&coord, &org).await,
        AuthKeyRequest::Revoke { prefix } => {
            revoke_auth_key(&coord, &org, &auth.id, &subject, &prefix, now_i64).await
        }
    }
}

/// Membership is required to touch the org's auth keys — and the refusal is
/// audited.
///
/// Factored out of [`auth_keys`] so the browser surface ([`crate::api`]'s
/// `/api/v1/auth-keys`) applies the *same* rule and writes the *same*
/// `auth_key.denied` row, exactly as [`require_membership_to_approve`] does for
/// node approval. Two surfaces onto one credential must not disagree about who
/// may mint it, and an audit log with two differently-named refusal actions is
/// one nobody can query.
///
/// Mirrors `self_register`: a valid session whose membership was revoked must
/// not keep minting enrollment credentials.
///
/// # Errors
///
/// The `403` / `500` [`Response`] to return, on refusal or a database failure.
#[allow(clippy::result_large_err)]
pub(crate) async fn require_membership_for_auth_keys(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    now: i64,
) -> Result<(), Response> {
    match coord.db().role_of(org, user_id).await {
        Ok(Some(_role)) => Ok(()),
        Ok(None) => {
            let _ = coord
                .db()
                .scoped(org.clone())
                .append_audit(&AuditEntry {
                    ts: now,
                    subject: Some(user_id),
                    action: "auth_key.denied",
                    node: None,
                    board: None,
                    lease: None,
                    detail: Some("not a member of the org the session belongs to"),
                })
                .await;
            warn!(org = %org, subject = %user_id, "auth-key request by a non-member");
            Err(reject(StatusCode::FORBIDDEN, "forbidden"))
        }
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
        }
    }
}

/// Mint an auth key for `org` on behalf of `user_id`.
///
/// The secret exists exactly once, in this response: only its SHA-256 is
/// stored. `created_by` is finally populated on this path, which is what lets
/// the creator revoke their own key later.
///
/// `pub(crate)` for [`crate::api`], which **calls** it rather than forking the
/// validation: `ttl_secs = 0`, the TTL cap, the `purpose` allowlist, the
/// tagless-`ci` refusal and the op normalisation are one implementation or they
/// are two that will disagree.
// One argument per column, as `insert_auth_key` has: the columns are the key's
// whole definition and bundling them would only move the same list down a
// level.
#[allow(clippy::too_many_arguments)]
// Linear for the same reason [`exchange_workload_key`] is: this is a sequence of
// independent refusals, each with its own paragraph saying why, and splitting it
// would scatter the mint's validation across functions that must agree.
#[allow(clippy::too_many_lines)]
pub(crate) async fn create_auth_key(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    tags: Vec<String>,
    ttl_secs: u64,
    multi_use: bool,
    purpose: Option<&str>,
    ops: Vec<String>,
    subject_name: Option<&str>,
    now: i64,
) -> Response {
    // A forever-key over the API is refused rather than silently capped: the
    // caller asked for something this path does not do, and quietly giving them
    // a 30-day key would be discovered a month later.
    if ttl_secs == 0 || ttl_secs > MAX_API_AUTH_KEY_TTL_SECS {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // An unrecognised purpose is a 400, never a silent default. The two
    // purposes are *different credentials* — one offers hardware, one leases it
    // — so a typo'd `--purpose ic` quietly meaning `node` would mint the wrong
    // thing and only fail at redemption, far from the mistake.
    let purpose = match purpose {
        None => crate::state::AUTH_KEY_PURPOSE_NODE,
        Some(p) if p == crate::state::AUTH_KEY_PURPOSE_NODE => {
            crate::state::AUTH_KEY_PURPOSE_NODE
        }
        Some(p) if p == crate::state::AUTH_KEY_PURPOSE_CI => crate::state::AUTH_KEY_PURPOSE_CI,
        Some(_) => return reject(StatusCode::BAD_REQUEST, "invalid_request"),
    };

    // The identity name (`--as <name>`), validated by the one shared validator.
    //
    // A name on a `node` key is a `400`, not a stored no-op: a node key confers
    // no subject for a name to attach to, so silently accepting it would leave
    // an operator holding a flag that looks effective and is not. An invalid
    // name is likewise a `400` rather than a repair — a repaired name is a
    // *different identity*, and the whole point is that the operator can retype
    // the same one months later.
    let subject_name = match subject_name {
        None => None,
        Some(_) if purpose != crate::state::AUTH_KEY_PURPOSE_CI => {
            return reject(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Some(raw) => match fleet_proto::ids::normalise_agent_name(raw) {
            Some(name) => Some(name),
            None => return reject(StatusCode::BAD_REQUEST, "invalid_request"),
        },
    };

    let mut tags = tags;
    tags.sort_unstable();
    tags.dedup();

    // A CI key's tags become the *selector* of the grant its redemption
    // synthesises, and an empty selector matches every board in the org. The
    // selector parser refuses an empty expression at every other entry point
    // (§6.5); refusing it here keeps that rule from having an exception nobody
    // would find until a runner had the whole fleet.
    if purpose == crate::state::AUTH_KEY_PURPOSE_CI && tags.is_empty() {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // For the same reason, the tags must survive the trip *through* the
    // selector grammar: a tag like `*` now parses to `NoWildcard` and would
    // turn a mint-time typo into a failed redemption far from its cause.
    // `valid_tags` is the rule node registration and the browser's node `PATCH`
    // already apply, so this removes an exception rather than adding a rule --
    // and with it, "validated at mint" implies "parses at redemption".
    if !tags.is_empty() && !valid_tags(&tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Ops are validated here so a typo is a 400 rather than an op silently
    // dropped at redemption.
    let normalized_ops: Vec<String> = if ops.is_empty() {
        Vec::new()
    } else {
        let parsed: Vec<fleet_proto::token::AllowedOp> = match ops
            .iter()
            .map(|o| fleet_proto::token::AllowedOp::from_label(o))
            .collect::<Option<Vec<_>>>()
        {
            Some(parsed) => fleet_proto::token::normalize_ops(parsed),
            None => return reject(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        parsed.iter().map(|o| o.as_str().to_owned()).collect()
    };

    let expires = now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX));

    let token = OpaqueToken::mint(TokenKind::AuthKey);
    if let Err(e) = coord
        .db()
        .insert_auth_key_with_purpose(
            org,
            token.hash().as_str(),
            &tags,
            !multi_use,
            Some(expires),
            Some(user_id),
            now,
            purpose,
            &normalized_ops,
            subject_name.as_deref(),
        )
        .await
    {
        warn!(error = %e, "failed to record an auth key");
        return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }

    // Subject is the **user**, as in `self_register` and unlike
    // `redeem_auth_key`: a human's authority created this credential, and that
    // is the fact worth being able to look up later.
    let detail = match subject_name.as_deref() {
        Some(name) => format!(
            "minted by {user_id} (purpose={purpose}, as={name}, single_use={}, tags=[{}])",
            !multi_use,
            tags.join(",")
        ),
        None => format!(
            "minted by {user_id} (purpose={purpose}, single_use={}, tags=[{}])",
            !multi_use,
            tags.join(",")
        ),
    };
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(user_id),
            action: "auth_key.mint",
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(
        org = %org, subject = %user_id, key = %token.hash().short(), %purpose,
        identity = subject_name.as_deref().unwrap_or("-"),
        "auth key minted"
    );

    Json(AuthKeyCreated {
        key: token.to_secret_string(),
        key_hash: token.hash().as_str().to_owned(),
        org: org.0.clone(),
        tags,
        single_use: !multi_use,
        purpose: purpose.to_owned(),
        subject_name,
        expires: Some(expires),
    })
    .into_response()
}

/// List `org`'s auth keys. Hash-only, so the listing is never a credential.
///
/// `pub(crate)` for [`crate::api`]; see [`create_auth_key`].
pub(crate) async fn list_auth_keys(coord: &Coordinator, org: &OrgId) -> Response {
    let keys = match coord.db().list_auth_keys(org).await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(error = %e, "failed to list auth keys");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    Json(AuthKeyList {
        org: org.0.clone(),
        keys: keys
            .into_iter()
            .map(|k| AuthKeyInfo {
                key_hash: k.key_hash,
                tags: k.tags,
                single_use: k.single_use,
                purpose: k.purpose,
                subject_name: k.subject_name,
                expires: k.expires,
                consumed_at: k.consumed_at,
                created_at: k.created_at,
                created_by: k.created_by,
            })
            .collect(),
    })
    .into_response()
}

/// Revoke `org`'s auth keys by hash prefix.
///
/// Authorization mirrors lease ownership (§6.5): the **creator** may revoke
/// their own key, an **org admin** may revoke any of the org's keys — including
/// the shell-minted ones whose `created_by` is `NULL`, which would otherwise be
/// unrevokable from here.
///
/// `pub(crate)` for [`crate::api`]; see [`create_auth_key`]. The CI-grant
/// revocation cascade below is the reason forking this would be worse than it
/// looks — a second implementation that forgot it would leave a runner relaying
/// bytes on a board whose key the operator believes is dead.
pub(crate) async fn revoke_auth_key(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    subject: &Subject,
    prefix: &str,
    now: i64,
) -> Response {
    let prefix = prefix.trim().to_ascii_lowercase();
    // Load-bearing, not hygiene: `delete_auth_keys_by_prefix` with an empty
    // prefix is `LIKE '%'`, i.e. every key in the org. A short or non-hex
    // prefix cannot address a key on purpose, so it is refused outright.
    if prefix.len() < MIN_AUTH_KEY_PREFIX_LEN || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }

    let keys = match coord.db().list_auth_keys(org).await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(error = %e, "failed to list auth keys");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let matches: Vec<_> = keys
        .iter()
        .filter(|k| k.key_hash.starts_with(&prefix))
        .collect();
    let target = match matches.len() {
        0 => return reject(StatusCode::NOT_FOUND, "not_found"),
        1 => matches[0],
        // Unlike `roles::admin::auth_key_revoke`, the candidates are *not*
        // named: that verb has the database locally, this one is on the far
        // side of a deliberately coarse `ErrorResponse`. The CLI turns this
        // code into "run `auth-key list` and use a longer prefix".
        _ => return reject(StatusCode::CONFLICT, "ambiguous_prefix"),
    };

    let owned = target.created_by.as_deref() == Some(user_id);
    if !owned && !crate::authz::is_org_admin(coord.db(), subject).await {
        let _ = coord
            .db()
            .scoped(org.clone())
            .append_audit(&AuditEntry {
                ts: now,
                subject: Some(user_id),
                action: "auth_key.revoke.denied",
                node: None,
                board: None,
                lease: None,
                detail: Some("neither the key's creator nor an org admin"),
            })
            .await;
        warn!(org = %org, subject = %user_id, "auth-key revocation by a non-owner");
        return reject(StatusCode::FORBIDDEN, "forbidden");
    }

    let revoked = match coord.db().delete_auth_keys_by_prefix(org, &prefix).await {
        Ok(revoked) => revoked,
        Err(e) => {
            warn!(error = %e, "failed to revoke an auth key");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    // Revoking a CI key must also revoke the grant its redemption synthesised
    // (architecture §6.7), for the reason §6.5 gives about grant revocation:
    // deleting the credential alone would leave the runner relaying bytes on a
    // board it may no longer use until the lease TTL ran out, while the
    // operator believed the key was dead. `revoke_grant_by_id` goes through the
    // whole release path — channels down, lease closed and audited, waiters
    // promoted — so revocation here is as real as it is there.
    let mut cascaded: Vec<String> = Vec::new();
    for hash in &revoked {
        // The same two-arm selection the redemption path uses — a named key's
        // grant id is a function of `(org, name)`, not of the hash, so
        // recomputing `ci-<hash>` here would leave the identity's grant (and
        // every lease under it) standing while reporting success.
        //
        // Safe to read `target.subject_name`: an ambiguous prefix was refused
        // above, so exactly one key row is in play.
        let grant_id = match target.subject_name.as_deref() {
            Some(name) => named_ci_grant_id(org, name),
            None => format!("ci-{}", hash.get(..29).unwrap_or(hash)),
        };
        match coord.revoke_grant_by_id(org, &grant_id).await {
            Ok(ids) => cascaded.extend(ids),
            // A failure here must not swallow the revocation that already
            // happened: the key is gone either way, and an operator needs to
            // know a lease may still be live.
            Err(e) => warn!(error = %e, %grant_id, "failed to cascade a CI key's grant"),
        }
    }
    if !cascaded.is_empty() {
        info!(grants = %cascaded.join(","), "revoked the grants a CI auth key had synthesised");
    }

    let detail = if cascaded.is_empty() {
        format!("revoked by {user_id}: {}", revoked.join(","))
    } else {
        format!(
            "revoked by {user_id}: {} (cascaded grants {})",
            revoked.join(","),
            cascaded.join(",")
        )
    };
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(user_id),
            action: "auth_key.revoke",
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(org = %org, subject = %user_id, count = revoked.len(), "auth keys revoked");

    Json(AuthKeyRevoked {
        org: org.0.clone(),
        revoked,
    })
    .into_response()
}


/// Provision the org/user/member chain and mint a user session token.
///
/// This is the **interim admin** path (`coordinator user-token`): it derives
/// `user.id` from the login it was handed, because there is no GitHub identity
/// to key off. The device flow deliberately does *not* come through here — it
/// calls [`mint_session_for_user`] against a `gh-<id>`-keyed user that
/// `Db::upsert_github_user` created. Going through `ensure_user_member` would
/// create a second, login-keyed user row and defeat that.
///
/// A consequence worth stating: `coordinator user-token alice` and alice's own
/// `probe-rs-fleet login` produce **two distinct subjects** for one human, so a
/// lease held under one is not controllable by the other
/// (`authz::require_lease_control` keys off `SubjectKey`). Tolerable for an
/// interim verb; surprising if undocumented.
///
/// Membership matters here: a session token is useless without a `member` row,
/// because `authz::require_role` consults membership and an authenticated
/// non-member is denied by construction — `ctl list` would fail closed on a
/// perfectly valid token.
///
/// Order is load-bearing: `user.personal_org_id` and `session.user_id` are
/// enforced foreign keys, so org → user → member → session.
///
/// # Errors
///
/// Returns a database error if any write fails.
pub async fn mint_session(
    coord: &Coordinator,
    org: &OrgId,
    login: &str,
    role: Role,
    ttl_secs: u64,
) -> crate::error::Result<(String, i64)> {
    coord.db().ensure_org(org, "personal").await?;
    coord.db().ensure_user_member(org, login, role).await?;
    mint_session_for_user(
        coord,
        org,
        login,
        ttl_secs,
        "interim admin-minted session token",
    )
    .await
}

/// Mint a session token for an **already provisioned** user.
///
/// Insert + audit only: no org, user or member row is created, so the caller
/// must have provisioned them (the foreign key on `session.user_id` turns a
/// mistake here into a loud failure rather than a valid token belonging to
/// nobody).
///
/// # Errors
///
/// Returns a database error if the insert fails.
pub async fn mint_session_for_user(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    ttl_secs: u64,
    audit_detail: &str,
) -> crate::error::Result<(String, i64)> {
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let expires = now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX));

    let token = OpaqueToken::mint(TokenKind::Session);
    coord
        .db()
        .insert_session(token.hash().as_str(), org, user_id, now, expires)
        .await?;

    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(user_id),
            action: "session.mint",
            node: None,
            board: None,
            lease: None,
            detail: Some(audit_detail),
        })
        .await;

    Ok((token.to_secret_string(), expires))
}

/// Build the GitHub OAuth client from configuration, or produce the named 503.
///
/// The `Err` variant is a whole `Response` rather than a code, because the two
/// call sites want to return it verbatim; it is built once per request on a path
/// that is already making network calls, so its size is not worth a `Box`.
#[allow(clippy::result_large_err)]
pub(crate) fn github_app(coord: &Coordinator) -> Result<GithubApp, Response> {
    let Some(cfg) = coord.config().github.as_ref() else {
        warn!(
            "a GitHub login request arrived but no [github] table is configured; \
             `probe-rs-fleet login` cannot work against this coordinator"
        );
        return Err(reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "device_flow_unconfigured",
        ));
    };
    Ok(GithubApp {
        client_id: cfg.client_id.clone(),
        client_secret: cfg.client_secret.clone(),
        scope: cfg.scope.clone(),
        endpoints: GithubEndpoints {
            device_code_url: cfg.device_code_url.clone(),
            access_token_url: cfg.access_token_url.clone(),
            authorize_url: cfg.authorize_url.clone(),
            api_base: cfg.api_base.clone(),
        },
    })
}

/// `POST /auth/device/start` — begin a GitHub device flow.
///
/// Necessarily unauthenticated: the whole point is that the caller has no
/// credential yet.
async fn auth_device_start(
    State(coord): State<Arc<Coordinator>>,
    Json(_request): Json<DeviceStartRequest>,
) -> Response {
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };
    match github::start_device_flow(&app).await {
        Ok(grant) => Json(DeviceStartResponse {
            device_code: grant.device_code,
            user_code: grant.user_code,
            verification_uri: grant.verification_uri,
            interval: grant.interval,
            expires_in: grant.expires_in,
        })
        .into_response(),
        Err(e) => {
            warn!(error = %e, "failed to start a GitHub device flow");
            reject(StatusCode::BAD_GATEWAY, "upstream_error")
        }
    }
}

/// `POST /auth/device/poll` — redeem a device code for a fleet session token.
///
/// On `Granted` the GitHub access token is used **here and discarded**: it is
/// spent on one `GET /user` call, the numeric id provisions the user and its
/// personal org, and only a fleet session token is returned.
async fn auth_device_poll(
    State(coord): State<Arc<Coordinator>>,
    Json(request): Json<DevicePollRequest>,
) -> Response {
    let app = match github_app(&coord) {
        Ok(app) => app,
        Err(response) => return response,
    };
    if request.device_code.trim().is_empty() {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }

    let access_token = match github::poll_device_flow(&app, &request.device_code).await {
        Ok(DevicePoll::Granted { access_token }) => access_token,
        // Relayed verbatim: these describe the caller's own device code, so the
        // CLI can drive its poll loop. See the module docs on the no-oracle
        // discipline.
        Ok(DevicePoll::Pending) => {
            return reject(StatusCode::UNAUTHORIZED, "authorization_pending")
        }
        Ok(DevicePoll::SlowDown { .. }) => {
            return reject(StatusCode::TOO_MANY_REQUESTS, "slow_down")
        }
        Ok(DevicePoll::Expired) => return reject(StatusCode::UNAUTHORIZED, "expired_token"),
        Ok(DevicePoll::Denied) => return reject(StatusCode::UNAUTHORIZED, "access_denied"),
        Err(e) => {
            warn!(error = %e, "GitHub device-flow poll failed");
            return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
        }
    };

    let user = match github::fetch_user(&app, &access_token).await {
        Ok(user) => user,
        Err(e) => {
            warn!(error = %e, "could not read the GitHub user behind a granted device flow");
            return reject(StatusCode::BAD_GATEWAY, "upstream_error");
        }
    };

    // The immutable numeric id is the identity; `login` is cached for display
    // and refreshed here. Keying off the login would let a rename + re-claim
    // land the new owner in the old owner's org (see `Db::upsert_github_user`).
    let Ok(gh_id) = i64::try_from(user.id) else {
        return reject(StatusCode::BAD_GATEWAY, "upstream_error");
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
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
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
                detail: Some("github device flow: personal org created"),
            })
            .await;
        info!(user = %user_id, org = %org, "provisioned a user and its personal org");
    }

    let ttl = coord.config().session_ttl_secs;
    let (token, expires) =
        match mint_session_for_user(&coord, &org, &user_id, ttl, "github device flow").await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to mint a session token after a device flow");
                return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        };

    Json(TokenResponse {
        token,
        node_id: None,
        org: org.0,
        orgs: Vec::new(),
        expires: u64::try_from(expires).ok(),
        coordinator_token_pubkey: None,
        login: Some(user.login),
    })
    .into_response()
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

/// `POST /node/register/start` — begin an approval-pending node registration.
///
/// Necessarily unauthenticated: the calling machine has no credential, which is
/// what the ceremony exists to fix. Everything in the body is therefore
/// attacker-controlled and validated before it is stored.
///
/// The source address comes from the connection, and the extractor is
/// deliberately `Option<Extension<ConnectInfo<..>>>` rather than
/// `ConnectInfo<..>`: a serve path that does not inject it (every test harness,
/// and anything else built with a plain `axum::serve`) then records
/// `source_ip = NULL` — the behaviour already documented as correct behind an
/// opaque proxy — instead of failing the request. `X-Forwarded-For` is not
/// consulted: it is an unauthenticated header, so trusting it would let the
/// requester choose what the approver sees, which is worse than showing
/// nothing.
async fn node_register_start(
    State(coord): State<Arc<Coordinator>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(request): Json<NodeRegisterStartRequest>,
) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    let node_name = request.node_name.trim();
    if !valid_node_name(node_name) || !valid_tags(&request.tags) {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Default `auto`: a human is standing over this enrollment and approving it
    // live, which is the `share` situation rather than the disk-image one.
    let adopt = match parse_adopt(request.adopt.as_deref(), AdoptPolicy::Auto) {
        Ok(adopt) => adopt,
        Err(response) => return response,
    };

    // The cap is checked before the write, not after: the point is to bound an
    // unauthenticated caller's ability to grow this table at all.
    match coord.db().live_pending_node_count(now_i64).await {
        Ok(live) if live >= coord.config().max_pending_nodes => {
            warn!(
                live,
                "pending node registrations are at the configured ceiling; refusing a new one"
            );
            return reject(StatusCode::SERVICE_UNAVAILABLE, "too_many_pending");
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "failed to count pending node registrations");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }

    let mut tags = request.tags;
    tags.sort_unstable();
    tags.dedup();

    let device = OpaqueToken::mint(TokenKind::NodeDevice);
    let ttl = coord.config().pending_node_ttl_secs;
    let expires = now_i64.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX));
    let source_ip = peer.map(|Extension(ConnectInfo(addr))| addr.ip().to_string());

    let code = match coord
        .db()
        .insert_pending_node(
            fleet_auth::user_code::generate,
            device.hash().as_str(),
            node_name,
            &tags,
            adopt,
            source_ip.as_deref(),
            now_i64,
            expires,
        )
        .await
    {
        Ok(code) => code,
        Err(e) => {
            warn!(error = %e, "failed to record a pending node registration");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    info!(
        node_name,
        source_ip = source_ip.as_deref().unwrap_or("(unknown)"),
        "node registration awaiting approval"
    );

    Json(NodeRegisterStartResponse {
        user_code: fleet_auth::user_code::display(&code),
        device_secret: device.to_secret_string(),
        // No code in the URL, ever: the page reflects nothing (see
        // `node_approve_page`), and the code is printed separately by the
        // enrolling machine, exactly as GitHub's device flow does.
        verification_uri: format!(
            "{}/node/approve",
            coord.config().public_url.trim_end_matches('/')
        ),
        interval: 5,
        expires_in: ttl,
    })
    .into_response()
}

/// `POST /node/register/poll` — redeem an approved registration for a node
/// token.
///
/// Outcomes are relayed verbatim, exactly as `/auth/device/poll` documents:
/// these describe *the caller's own* pending registration, which it created, so
/// naming them is not an oracle about anybody else's credential.
///
/// **`access_denied` is not guaranteed to be observed.** The sweep deletes
/// consumed rows, and a denial marks the row consumed, so a sweep landing
/// between the denial and the machine's next poll downgrades the answer to
/// `expired_token` — the agent then reports the code as expired for a machine
/// that was in fact explicitly denied. Accepted: the sweep interval is short
/// relative to the poll interval so it is rare, the remediation is identical
/// either way, and keeping denied rows around purely to improve one log line
/// would mean an unauthenticated caller can pin rows against
/// `max_pending_nodes` until their TTL. Do not treat `access_denied` as a
/// reliable signal.
async fn node_register_poll(
    State(coord): State<Arc<Coordinator>>,
    Json(request): Json<NodeRegisterPollRequest>,
) -> Response {
    let now = coord.now();
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    // Wrong kind is `invalid_grant`, not a 403: the caller supplied a secret we
    // do not recognise as one of ours, which is indistinguishable from an
    // unknown one and must stay that way.
    let Ok(device) = OpaqueToken::parse(&request.device_secret) else {
        return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
    };
    if device.kind() != TokenKind::NodeDevice {
        return reject(StatusCode::UNAUTHORIZED, "invalid_grant");
    }
    let hash = device.hash();

    let pending = match coord
        .db()
        .pending_node_by_device_hash(hash.as_str(), now_i64)
        .await
    {
        Ok(Some(pending)) => pending,
        // Unknown, expired, or swept: all `expired_token`, deliberately and
        // uniformly. The lookup filters by TTL, so a live row past its expiry
        // and a row the sweep has already deleted arrive here identically — and
        // a well-formed `prfnd1_` secret nobody issued is indistinguishable
        // from one whose row aged out. The plan's outcome table said
        // `unknown → invalid_grant`; this is the deliberate deviation, because
        // the distinction is not knowable after a sweep and the agent's
        // remediation ("run `agent up` again for a fresh code") is the same for
        // all three.
        Ok(None) => {
            return reject(StatusCode::UNAUTHORIZED, "expired_token");
        }
        Err(e) => {
            warn!(error = %e, "failed to look up a pending node registration");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    if pending.is_pending() {
        return reject(StatusCode::UNAUTHORIZED, "authorization_pending");
    }
    if pending.is_denied() {
        return reject(StatusCode::UNAUTHORIZED, "access_denied");
    }

    // The single atomic consume is what makes redemption single-use under
    // concurrent polling; every check above is a courtesy that lets this route
    // say *why*, not the guard.
    let consumed = match coord
        .db()
        .consume_pending_node(hash.as_str(), now_i64)
        .await
    {
        Ok(Some(consumed)) => consumed,
        // Approved a moment ago but already redeemed (or redeemed by a racing
        // poll): nothing more to mint.
        Ok(None) => return reject(StatusCode::UNAUTHORIZED, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to consume a pending node registration");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let (org, approver, node_name, tags, adopt) = consumed;

    let detail = format!(
        "approved by {approver} (adopt={adopt}, code={})",
        pending.user_code
    );
    mint_node_token(
        &coord,
        &org,
        &node_name,
        &tags,
        &approver,
        adopt,
        "node.approve_register",
        &detail,
        now_i64,
    )
    .await
}

/// `POST /node/register/approve` — inspect, approve or deny a pending
/// registration.
///
/// Authenticated with a **session** token; the org and the approver come from
/// that session and never from the request, so an approval cannot bind a node
/// into an org the caller is not in. **Membership is sufficient** (§6.4/§6.5),
/// and the membership check is not decorative: `authz::require_role` denies a
/// non-member everywhere else, so a node created for one would be an orphan its
/// "owner" could never use.
async fn node_register_approve(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    Json(request): Json<NodeApprovalRequest>,
) -> Response {
    let (auth, _subject) = match authenticate_request(&coord, &headers, &[TokenKind::Session]).await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    let org = OrgId(auth.org_id.clone());
    let now_i64 = i64::try_from(coord.now()).unwrap_or(i64::MAX);

    match require_membership_to_approve(&coord, &org, &auth.id, now_i64).await {
        Ok(()) => {}
        Err(response) => return response,
    }

    decide_pending_node(
        &coord,
        &org,
        &auth.id,
        &request.user_code,
        request.decision,
        request.replace,
        now_i64,
    )
    .await
}

/// Membership is sufficient to approve — and the check is not decorative.
///
/// Factored out of [`node_register_approve`] so the browser surface
/// ([`crate::api`]'s `POST /api/v1/nodes/pending/{code}`) applies the *same*
/// rule and writes the *same* `node.approve.denied` audit row. Two surfaces
/// onto one ceremony must not disagree about who may perform it, and an audit
/// log with two differently-named refusal actions is one nobody can query.
///
/// `authz::require_role` denies a non-member everywhere else, so a node created
/// for one would be an orphan its "owner" could never use.
///
/// # Errors
///
/// The `403` / `500` [`Response`] to return, on refusal or a database failure.
#[allow(clippy::result_large_err)]
pub(crate) async fn require_membership_to_approve(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    now: i64,
) -> Result<(), Response> {
    match coord.db().role_of(org, user_id).await {
        Ok(Some(_role)) => Ok(()),
        Ok(None) => {
            let _ = coord
                .db()
                .scoped(org.clone())
                .append_audit(&AuditEntry {
                    ts: now,
                    subject: Some(user_id),
                    action: "node.approve.denied",
                    node: None,
                    board: None,
                    lease: None,
                    detail: Some("not a member of the org the session belongs to"),
                })
                .await;
            warn!(org = %org, subject = %user_id, "node approval by a non-member");
            Err(reject(StatusCode::FORBIDDEN, "forbidden"))
        }
        Err(e) => {
            warn!(error = %e, "failed to resolve membership");
            Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
        }
    }
}

/// Decide a pending registration on behalf of an already-resolved subject.
///
/// **The seam that keeps a browser flow possible.** Approval is a pure function
/// of `(code, decision, authenticated user)`: this function takes the subject
/// rather than resolving it, so a future cookie-authenticated web handler
/// resolves its subject its own way and calls exactly this — no schema change,
/// no second binding site. See the module documentation.
pub(crate) async fn decide_pending_node(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    raw_code: &str,
    decision: NodeApprovalDecision,
    replace: bool,
    now: i64,
) -> Response {
    // Unknown / malformed / expired / already-decided are all one answer: a
    // caller learns nothing about which of them it was.
    let Some(code) = fleet_auth::user_code::normalise(raw_code) else {
        return reject(StatusCode::NOT_FOUND, "invalid_grant");
    };
    let pending = match coord.db().pending_node_by_code(&code, now).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return reject(StatusCode::NOT_FOUND, "invalid_grant"),
        Err(e) => {
            warn!(error = %e, "failed to look up a pending node registration");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    // Resolved here and not earlier: there is no org until an approver appears,
    // so "does this name already exist?" is only answerable now, against *this*
    // approver's org.
    let collides_with = match coord
        .db()
        .node_id_in_org_by_name(org, &pending.node_name)
        .await
    {
        Ok(existing) => existing,
        Err(e) => {
            warn!(error = %e, "failed to check for a node-name collision");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    // `org` is the **approver's** org on every decision, including `Inspect`
    // — not the pending row's, which is NULL until the approval binds it. The
    // whole response is approver-relative already (`collides_with` is resolved
    // against this org), and "which org am I granting hardware access in" is
    // part of the decision the ceremony asks the human to make: a person may
    // hold sessions for several orgs, and the inspect screen is the only place
    // that question gets answered before they answer it.
    let describe = |pending: &crate::state::PendingNode, state: &str| NodeApprovalResponse {
        user_code: fleet_auth::user_code::display(&pending.user_code),
        node_name: pending.node_name.clone(),
        tags: pending.tags.clone(),
        adopt: pending.adopt.as_str().to_owned(),
        source_ip: pending.source_ip.clone(),
        created_at: pending.created_at,
        expires: pending.expires,
        org: Some(org.0.clone()),
        state: state.to_owned(),
        collides_with: collides_with.clone(),
    };

    let (action, detail) = match decision {
        NodeApprovalDecision::Inspect => {
            audit_inspect(coord, org, user_id, &code, &pending.node_name, now).await;
            return Json(describe(&pending, pending.state_label())).into_response();
        }
        NodeApprovalDecision::Approve => {
            match approve_pending(
                coord,
                org,
                user_id,
                &code,
                &pending,
                collides_with.as_deref(),
                replace,
                now,
            )
            .await
            {
                Ok(detail) => ("node.approve", detail),
                Err(response) => return response,
            }
        }
        NodeApprovalDecision::Deny => {
            match coord.db().deny_pending_node(&code, now).await {
                Ok(true) => {}
                Ok(false) => return reject(StatusCode::NOT_FOUND, "invalid_grant"),
                Err(e) => {
                    warn!(error = %e, "failed to deny a pending node registration");
                    return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                }
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
            ts: now,
            subject: Some(user_id),
            action,
            node: None,
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(org = %org, subject = %user_id, action, "pending node registration decided");

    let state = match decision {
        NodeApprovalDecision::Approve => "approved",
        NodeApprovalDecision::Deny => "denied",
        NodeApprovalDecision::Inspect => pending.state_label(),
    };
    // No org fixup here: `describe` already reports the approver's org on every
    // decision.
    Json(describe(&pending, state)).into_response()
}

/// Audit an inspection.
///
/// Inspecting changes nothing, but it is audited anyway: an authenticated
/// caller poking at codes is exactly what an operator wants to be able to see
/// after the fact, and it is the only trace the cross-tenant enumeration risk
/// leaves behind.
async fn audit_inspect(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    code: &str,
    node_name: &str,
    now: i64,
) {
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(user_id),
            action: "node.approve.inspect",
            node: None,
            board: None,
            lease: None,
            detail: Some(&format!("code={code} name={node_name}")),
        })
        .await;
}

/// Bind a pending registration to `org` / `user_id`, refusing a takeover.
///
/// Returns the audit detail on success, or the whole rejection response.
///
/// The collision guard lives **here, in the handler**, not only in the CLI: the
/// route is reachable with curl, and the machine that chose `node_name` did so
/// before any org existed, so without this an approver could be talked into
/// silently re-credentialing a node their org is currently running.
///
/// Note it is a check-then-act across two statements, and therefore advisory
/// against a *concurrent* registration — it protects against a human misreading
/// a name, not against a race. The single-use property
/// ([`crate::state::Db::consume_pending_node`]) is unaffected and stays atomic.
#[allow(clippy::result_large_err)]
#[allow(clippy::too_many_arguments)]
async fn approve_pending(
    coord: &Coordinator,
    org: &OrgId,
    user_id: &str,
    code: &str,
    pending: &crate::state::PendingNode,
    collides_with: Option<&str>,
    replace: bool,
    now: i64,
) -> Result<String, Response> {
    if !pending.is_pending() {
        return Err(reject(StatusCode::NOT_FOUND, "invalid_grant"));
    }
    if let Some(existing) = collides_with {
        if !replace {
            warn!(org = %org, node = %existing, "refusing an approval that would take over an existing node");
            return Err(reject(StatusCode::CONFLICT, "node_name_taken"));
        }
    }
    match coord
        .db()
        .approve_pending_node(code, org, user_id, now)
        .await
    {
        Ok(true) => {}
        // Lost a race with another approval or a denial: uniform answer.
        Ok(false) => return Err(reject(StatusCode::NOT_FOUND, "invalid_grant")),
        Err(e) => {
            warn!(error = %e, "failed to approve a pending node registration");
            return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
        }
    }
    Ok(format!(
        "code={code} name={} adopt={}{}",
        pending.node_name,
        pending.adopt,
        collides_with.map_or_else(String::new, |n| format!(" replaced={n}"))
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_extraction_is_scheme_insensitive_and_trims() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer  prfn1_abc "),
        );
        assert_eq!(bearer_of(&headers), Some("prfn1_abc"));

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer prfn1_abc"),
        );
        assert_eq!(bearer_of(&headers), Some("prfn1_abc"));
    }

    /// A non-bearer scheme must not be silently treated as a credential: it is
    /// absent, and the caller gets the same 401 as if it had sent nothing.
    #[test]
    fn other_auth_schemes_are_not_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwdw=="),
        );
        assert_eq!(bearer_of(&headers), None);

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("prfn1_abc"),
        );
        assert_eq!(bearer_of(&headers), None);

        assert_eq!(bearer_of(&HeaderMap::new()), None);
    }

    /// The properties `named_ci_grant_id`'s doc comment claims, pinned: the id
    /// is deterministic, hex-bodied (so `grant_revoke_core`'s hex floor accepts
    /// it), inside the `ci-` namespace, and **org-separated** — which is the
    /// one that matters, because `grant.id` is a global primary key and
    /// `upsert_grant` does not rewrite `org_id`.
    #[test]
    fn a_named_grant_id_is_deterministic_hex_and_org_separated() {
        let acme = OrgId("acme".to_owned());
        let other = OrgId("other".to_owned());

        let id = named_ci_grant_id(&acme, "builder");
        assert_eq!(id, named_ci_grant_id(&acme, "builder"), "deterministic");
        assert!(id.starts_with("ci-"), "got {id}");
        assert_eq!(id.len(), 3 + 29);
        let body = id.strip_prefix("ci-").unwrap();
        assert!(
            body.chars().all(|c| c.is_ascii_hexdigit()),
            "the body must stay hex so `grant revoke` accepts it: {id}"
        );
        assert!(body.len() >= 8, "and long enough to be a legal prefix");

        // The cross-tenant trap: the same name in two orgs must be two rows.
        assert_ne!(id, named_ci_grant_id(&other, "builder"));
        // And two names in one org, obviously.
        assert_ne!(id, named_ci_grant_id(&acme, "builder2"));
    }
}
