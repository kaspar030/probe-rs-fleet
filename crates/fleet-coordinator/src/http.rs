//! The HTTP/`WebSocket` surface (architecture §3.5).
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /healthz` | anyone | liveness, for the proxy |
//! | `GET /agent` | nodes | `WebSocket` upgrade → the agent control plane |
//! | `GET /client` | users, workloads | `WebSocket` upgrade → the sidecar/ctl plane |
//! | `POST /auth/token` | node enrollment, session refresh | JSON token exchange |
//!
//! `POST /auth/device/*` (the GitHub device flow) is a later task and is
//! deliberately absent rather than stubbed: a route that exists and 501s is
//! indistinguishable, to a client, from one that is broken.
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

use fleet_auth::api::{ErrorResponse, TokenRequest, TokenResponse};
use fleet_auth::{AuthError, Authenticated, OpaqueToken, TokenKind};
use fleet_proto::ids::{AgentId, OrgId, Role, Subject, SubjectKind};

use crate::core::Coordinator;
use crate::state::AuditEntry;

/// Build the coordinator's router.
#[must_use]
pub fn router(coord: Arc<Coordinator>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/agent", get(agent_ws))
        .route("/client", get(client_ws))
        .route("/auth/token", post(auth_token))
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

/// Log or audit a failed authentication, then produce the uniform 401.
fn reject_authentication(e: &AuthError) -> Response {
    // No org is resolvable for any of these: the credential matched no row (or
    // no row was even looked up). Logged, not audited — see the module docs.
    warn!(reason = e.label(), detail = %e, "rejected an unauthenticated request");
    if let AuthError::Store(detail) = e {
        // A storage failure is our fault, not the caller's; still a 401 to the
        // caller (no oracle), but it must be visible as an operational problem.
        warn!(%detail, "credential store failed during authentication");
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
    })
    .into_response()
}

/// Provision the org/user/member chain and mint a user session token.
///
/// The interim admin path (`coordinator user-token`) and the future device flow
/// both land here, so there is one place that knows a session token is useless
/// without a `member` row: `authz::require_role` consults membership, and an
/// authenticated non-member is denied by construction. Getting this wrong makes
/// `ctl list` fail closed on a perfectly valid token.
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
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let expires = now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX));

    coord.db().ensure_org(org, "personal").await?;
    coord.db().ensure_user_member(org, login, role).await?;

    let token = OpaqueToken::mint(TokenKind::Session);
    coord
        .db()
        .insert_session(token.hash().as_str(), org, login, now, expires)
        .await?;

    let _ = coord
        .db()
        .scoped(org.clone())
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(login),
            action: "session.mint",
            node: None,
            board: None,
            lease: None,
            detail: Some("interim admin-minted session token"),
        })
        .await;

    Ok((token.to_secret_string(), expires))
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
