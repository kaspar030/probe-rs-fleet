//! Bearer-token verification: string in, authenticated identity out.
//!
//! The token's prefix decides which table is consulted, so this is one lookup,
//! not a search. Existence and expiry are checked here; **authorization is
//! not** — that is the coordinator's `authz` layer, operating on the `Subject`
//! it builds from [`Authenticated`].
//!
//! # No oracle
//!
//! [`AuthError`] distinguishes malformed / unknown / expired / wrong-kind so the
//! coordinator can *audit* precisely. Every variant must map to the same generic
//! 401 (or 403) response body: the caller learns that its credential did not
//! work, not why. Diagnosability lives in the coordinator's audit log and in the
//! client's own local error text.

use crate::store::TokenStore;
use crate::token::{OpaqueToken, TokenError, TokenHash, TokenKind};

/// Why a bearer token was rejected.
///
/// Detail for the audit log — **never** for the response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No `Authorization: Bearer …` header was present.
    #[error("missing bearer credential")]
    Missing,
    /// The credential did not parse as a fleet token.
    #[error("malformed bearer credential: {0}")]
    Malformed(TokenError),
    /// The credential parsed but matched no row.
    ///
    /// For a node token this is the *revoked node* case, and it is the one the
    /// operator most needs named: see the `auth.reject.node_unknown` audit event
    /// and the agent's `CredentialRejected` remediation text.
    #[error("unknown {0} token")]
    Unknown(TokenKind),
    /// The credential matched a row that has expired.
    #[error("expired {0} token")]
    Expired(TokenKind),
    /// A valid credential of the wrong kind for this route.
    #[error("{got} token is not valid on this route")]
    WrongKind {
        /// The kind presented.
        got: TokenKind,
    },
    /// The credential store failed.
    #[error("credential store error: {0}")]
    Store(String),
}

impl AuthError {
    /// A short stable label for the audit log / structured logging.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AuthError::Missing => "auth.reject.missing",
            AuthError::Malformed(_) => "auth.reject.malformed",
            AuthError::Unknown(TokenKind::Node) => "auth.reject.node_unknown",
            AuthError::Unknown(_) => "auth.reject.unknown",
            AuthError::Expired(_) => "auth.reject.expired",
            AuthError::WrongKind { .. } => "auth.wrong_kind",
            AuthError::Store(_) => "auth.reject.store_error",
        }
    }
}

/// A verified credential.
///
/// Deliberately **not** a [`fleet_proto::ids::Subject`]: constructing a subject
/// requires knowing about orgs and membership, which this crate does not. The
/// coordinator turns this into a `Subject` at its single resolution seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Which credential was presented.
    pub kind: TokenKind,
    /// The org the credential belongs to.
    ///
    /// For a node this is the node row's org — never a configured default. For
    /// a [`TokenKind::Workload`] it is the *namespace* half of the subject key
    /// (`gha`, or the granting org for the auth-key fallback), which on the
    /// OIDC path is **not** an org that exists in the database.
    pub org_id: String,
    /// The principal's id: a node id for [`TokenKind::Node`], a user id for
    /// [`TokenKind::Session`], `<owner>/<repo>` for [`TokenKind::Workload`].
    pub id: String,
    /// Expiry, epoch seconds, if the credential has one.
    pub expires: Option<u64>,
    /// The hash the credential matched, for rotation bookkeeping and audit.
    pub hash: TokenHash,
    /// When a node's current token was issued (epoch seconds). `None` for
    /// non-node credentials.
    pub token_issued_at: Option<u64>,
}

/// Verify a bearer credential against the store.
///
/// `bearer` is the raw credential (the value *after* `Bearer `). `now` is epoch
/// seconds.
///
/// Auth keys and node-device secrets are deliberately **not** accepted here:
/// both are redeemed at a route (`POST /auth/token`, `POST /node/register/*`)
/// rather than presented on a connection, so treating either as a connection
/// credential is [`AuthError::WrongKind`].
///
/// # Errors
///
/// Returns [`AuthError`] on any rejection. Every variant maps to the same
/// generic response; the distinction is for auditing.
pub async fn authenticate(
    store: &impl TokenStore,
    bearer: &str,
    now: u64,
) -> Result<Authenticated, AuthError> {
    let bearer = bearer.trim();
    if bearer.is_empty() {
        return Err(AuthError::Missing);
    }
    let token = OpaqueToken::parse(bearer).map_err(AuthError::Malformed)?;
    let hash = token.hash();

    match token.kind() {
        TokenKind::Node => {
            let node = store
                .lookup_node(&hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(TokenKind::Node))?;
            Ok(Authenticated {
                kind: TokenKind::Node,
                org_id: node.org_id,
                id: node.node_id,
                expires: None,
                hash,
                token_issued_at: Some(node.token_issued_at),
            })
        }
        TokenKind::Session => {
            let session = store
                .lookup_session(&hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(TokenKind::Session))?;
            if session.expires <= now {
                return Err(AuthError::Expired(TokenKind::Session));
            }
            Ok(Authenticated {
                kind: TokenKind::Session,
                org_id: session.org_id,
                id: session.user_id,
                expires: Some(session.expires),
                hash,
                token_issued_at: None,
            })
        }
        TokenKind::Workload => {
            let workload = store
                .lookup_workload(&hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(TokenKind::Workload))?;
            if workload.expires <= now {
                return Err(AuthError::Expired(TokenKind::Workload));
            }
            Ok(Authenticated {
                kind: TokenKind::Workload,
                // The reserved `gha` namespace, not an org: a workload belongs
                // to no tenant and reaches boards only through grants.
                org_id: workload.org_id,
                id: workload.id,
                expires: Some(workload.expires),
                hash,
                token_issued_at: None,
            })
        }
        TokenKind::AuthKey => Err(AuthError::WrongKind {
            got: TokenKind::AuthKey,
        }),
        TokenKind::NodeDevice => Err(AuthError::WrongKind {
            got: TokenKind::NodeDevice,
        }),
    }
}

/// Verify an auth key presented to `POST /auth/token`, without consuming it.
///
/// Consumption is a single atomic store operation the coordinator performs, so
/// that a single-use key cannot be redeemed twice concurrently; this call is the
/// shape/expiry pre-check that lets the caller reject cheaply and audit
/// precisely.
///
/// # Errors
///
/// Returns [`AuthError`] if the key is malformed, of the wrong kind, unknown or
/// expired.
pub async fn verify_auth_key(
    store: &impl TokenStore,
    key: &str,
    now: u64,
) -> Result<(TokenHash, crate::store::AuthKeyRecord), AuthError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(AuthError::Missing);
    }
    let token = OpaqueToken::parse(key).map_err(AuthError::Malformed)?;
    if token.kind() != TokenKind::AuthKey {
        return Err(AuthError::WrongKind { got: token.kind() });
    }
    let hash = token.hash();
    let record = store
        .lookup_auth_key(&hash)
        .await
        .map_err(AuthError::Store)?
        .ok_or(AuthError::Unknown(TokenKind::AuthKey))?;
    if record.expires.is_some_and(|e| e <= now) {
        return Err(AuthError::Expired(TokenKind::AuthKey));
    }
    Ok((hash, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fake::FakeStore;
    use crate::store::{AuthKeyRecord, NodeRecord, SessionRecord};

    fn node_token() -> OpaqueToken {
        OpaqueToken::mint(TokenKind::Node)
    }

    #[tokio::test]
    async fn node_token_resolves_to_its_row_org() {
        let token = node_token();
        let store = FakeStore::default().with_node(
            &token.hash(),
            NodeRecord {
                node_id: "node-a".to_owned(),
                org_id: "acme".to_owned(),
                token_issued_at: 100,
            },
        );
        let auth = authenticate(&store, &token.to_secret_string(), 1_000)
            .await
            .unwrap();
        assert_eq!(auth.kind, TokenKind::Node);
        assert_eq!(auth.id, "node-a");
        // The org comes from the node row, not from any configured default.
        assert_eq!(auth.org_id, "acme");
        assert_eq!(auth.token_issued_at, Some(100));
    }

    #[tokio::test]
    async fn session_token_resolves_and_expires() {
        let token = OpaqueToken::mint(TokenKind::Session);
        let store = FakeStore::default().with_session(
            &token.hash(),
            SessionRecord {
                user_id: "alice".to_owned(),
                org_id: "acme".to_owned(),
                expires: 1_000,
            },
        );
        let s = token.to_secret_string();
        let auth = authenticate(&store, &s, 999).await.unwrap();
        assert_eq!(auth.id, "alice");
        assert_eq!(auth.expires, Some(1_000));
        // Boundary: expiry is exclusive — `now == expires` is already expired.
        assert_eq!(
            authenticate(&store, &s, 1_000).await.unwrap_err(),
            AuthError::Expired(TokenKind::Session)
        );
        assert_eq!(
            authenticate(&store, &s, 1_001).await.unwrap_err(),
            AuthError::Expired(TokenKind::Session)
        );
    }

    /// A revoked node is a deleted row: the very next authentication fails, and
    /// it fails as `node_unknown` so the operator can tell it apart from noise.
    #[tokio::test]
    async fn revoked_node_is_unknown_and_distinctly_labelled() {
        let token = node_token();
        let store = FakeStore::default();
        let err = authenticate(&store, &token.to_secret_string(), 10)
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::Unknown(TokenKind::Node));
        assert_eq!(err.label(), "auth.reject.node_unknown");
    }

    /// A workload token *is* a connection credential (unlike an auth key), and
    /// its namespace is the reserved `gha`, not an org row.
    #[tokio::test]
    async fn workload_token_resolves_and_expires() {
        use crate::store::WorkloadRecord;
        let token = OpaqueToken::mint(TokenKind::Workload);
        let store = FakeStore::default().with_workload(
            &token.hash(),
            WorkloadRecord {
                org_id: "gha".to_owned(),
                id: "ariel-os/ariel-os".to_owned(),
                expires: 1_000,
            },
        );
        let s = token.to_secret_string();
        let auth = authenticate(&store, &s, 999).await.unwrap();
        assert_eq!(auth.kind, TokenKind::Workload);
        assert_eq!(auth.org_id, "gha");
        assert_eq!(auth.id, "ariel-os/ariel-os");
        assert_eq!(auth.expires, Some(1_000));
        // Expiry is exclusive, as for a session: `now == expires` is expired.
        assert_eq!(
            authenticate(&store, &s, 1_000).await.unwrap_err(),
            AuthError::Expired(TokenKind::Workload)
        );
        // An unknown workload token (the exchange row swept, or forged) is a
        // plain unknown-token rejection.
        let other = OpaqueToken::mint(TokenKind::Workload);
        assert_eq!(
            authenticate(&store, &other.to_secret_string(), 0)
                .await
                .unwrap_err(),
            AuthError::Unknown(TokenKind::Workload)
        );
    }

    #[tokio::test]
    async fn missing_and_malformed_are_distinguished_for_audit_only() {
        let store = FakeStore::default();
        assert_eq!(
            authenticate(&store, "   ", 0).await.unwrap_err(),
            AuthError::Missing
        );
        assert!(matches!(
            authenticate(&store, "garbage", 0).await.unwrap_err(),
            AuthError::Malformed(_)
        ));
    }

    /// An auth key is redeemed at `/auth/token`; presenting one as a connection
    /// credential is a wrong-kind rejection, not an unknown-token one. A
    /// node-device secret is the same case at `/node/register/poll`.
    #[tokio::test]
    async fn auth_key_is_not_a_connection_credential() {
        let key = OpaqueToken::mint(TokenKind::AuthKey);
        let store = FakeStore::default().with_auth_key(
            &key.hash(),
            AuthKeyRecord {
                org_id: "acme".to_owned(),
                tags: vec![],
                single_use: true,
                expires: None,
            },
        );
        assert_eq!(
            authenticate(&store, &key.to_secret_string(), 0)
                .await
                .unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::AuthKey
            }
        );

        let device = OpaqueToken::mint(TokenKind::NodeDevice);
        assert_eq!(
            authenticate(&store, &device.to_secret_string(), 0)
                .await
                .unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::NodeDevice
            }
        );
    }

    #[tokio::test]
    async fn auth_key_verification_checks_kind_and_expiry() {
        let key = OpaqueToken::mint(TokenKind::AuthKey);
        let store = FakeStore::default().with_auth_key(
            &key.hash(),
            AuthKeyRecord {
                org_id: "acme".to_owned(),
                tags: vec!["nrf52".to_owned()],
                single_use: true,
                expires: Some(500),
            },
        );
        let s = key.to_secret_string();
        let (hash, record) = verify_auth_key(&store, &s, 499).await.unwrap();
        assert_eq!(hash, key.hash());
        assert_eq!(record.org_id, "acme");
        assert_eq!(record.tags, vec!["nrf52".to_owned()]);
        assert_eq!(
            verify_auth_key(&store, &s, 500).await.unwrap_err(),
            AuthError::Expired(TokenKind::AuthKey)
        );
        // A node token offered where an auth key is expected.
        let node = node_token().to_secret_string();
        assert_eq!(
            verify_auth_key(&store, &node, 0).await.unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::Node
            }
        );
    }
}
