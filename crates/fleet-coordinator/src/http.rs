//! The HTTP/`WebSocket` surface (architecture §3.5).
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /healthz` | anyone | liveness, for the proxy |
//! | `GET /agent` | nodes | `WebSocket` upgrade → the agent control plane |
//! | `GET /client` | users, workloads | `WebSocket` upgrade → the sidecar/ctl plane |
//! | `POST /auth/token` | node enrollment, session refresh | JSON token exchange |
//! | `POST /auth/device/start` | anyone | begin a GitHub device flow |
//! | `POST /auth/device/poll` | anyone | redeem a device code for a session token |
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

use std::sync::Arc;

use axum::extract::{ws::WebSocketUpgrade, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tracing::{debug, info, warn};

use fleet_auth::api::{
    DevicePollRequest, DeviceStartRequest, DeviceStartResponse, ErrorResponse, TokenRequest,
    TokenResponse,
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
        .route("/auth/token", post(auth_token))
        .route("/auth/device/start", post(auth_device_start))
        .route("/auth/device/poll", post(auth_device_poll))
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
fn reject(status: StatusCode, code: &str) -> Response {
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
    let now = coord.now();
    let bearer = bearer_of(headers).unwrap_or("");

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
        // `authenticate` never returns this kind; it is redeemed, not presented.
        TokenKind::AuthKey => {
            return Err(reject(StatusCode::FORBIDDEN, "forbidden"));
        }
    };
    Ok((auth, subject))
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
            if let Err(e) = crate::server::handle_agent(coord, Box::new(tx), Box::new(rx), agent_id.clone(), auth).await
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
async fn client_ws(
    State(coord): State<Arc<Coordinator>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (_auth, subject) =
        match authenticate_request(&coord, &headers, &[TokenKind::Session]).await {
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

    if node_name.trim().is_empty() {
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
        expires: None,
        coordinator_token_pubkey: Some(coord.token_pubkey_hex()),
        login: None,
    })
    .into_response()
}

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

    if node_name.trim().is_empty() {
        return reject(StatusCode::BAD_REQUEST, "invalid_request");
    }

    // An unrecognised policy is a 400, never a silent default: a typo'd
    // `adopt = "delcared"` quietly meaning `auto` would share probes the
    // operator did not mean to share. Absent means this grant's default, which
    // is `auto` — `share` is a deliberate "offer this machine's probes".
    let adopt = match adopt {
        None => AdoptPolicy::Auto,
        Some(label) => match AdoptPolicy::from_label(label) {
            Some(policy) => policy,
            None => return reject(StatusCode::BAD_REQUEST, "invalid_request"),
        },
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

    let token = OpaqueToken::mint(TokenKind::Node);
    let mut all_tags = tags;
    all_tags.sort_unstable();
    all_tags.dedup();

    let node = match coord
        .db()
        .register_node_full(
            &org,
            node_name,
            token.hash().as_str(),
            &all_tags,
            Some(&auth.id),
            adopt,
            now_i64,
        )
        .await
    {
        Ok(node) => node,
        Err(e) => {
            warn!(error = %e, "failed to register node");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    let detail = format!("self-registered by {} (adopt={adopt})", auth.id);
    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now_i64,
            subject: Some(auth.id.as_str()),
            action: "node.self_register",
            node: Some(node.0.as_str()),
            board: None,
            lease: None,
            detail: Some(&detail),
        })
        .await;
    info!(node = %node, org = %org, owner = %auth.id, %adopt, "node self-registered");

    Json(TokenResponse {
        token: token.to_secret_string(),
        node_id: Some(node.0),
        org: org.0,
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
    let expires = now_i64.saturating_add(
        i64::try_from(coord.config().session_ttl_secs).unwrap_or(i64::MAX),
    );
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
        expires: u64::try_from(expires).ok(),
        coordinator_token_pubkey: None,
        login: None,
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
fn github_app(coord: &Coordinator) -> Result<GithubApp, Response> {
    let Some(cfg) = coord.config().github.as_ref() else {
        warn!(
            "a device-flow request arrived but no [github] table is configured; \
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
        expires: u64::try_from(expires).ok(),
        coordinator_token_pubkey: None,
        login: Some(user.login),
    })
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
}
