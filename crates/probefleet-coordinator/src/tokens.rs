//! Node-token lookup: fleet's one app token kind, plugged into forgs'
//! authentication seam.
//!
//! forgs authenticates every credential through
//! `forgs_http::authenticate_request`; for the app kind `node` (prefix
//! `prfn1_`) it asks this [`AppTokenLookup`], keyed by the token's SHA-256
//! hash (the secret itself is never stored). The subject is
//! `<org ns id>/node:<node id>`, and its org comes from the node **row**, which
//! is what stops a node token from being replayed into another tenant.

use async_trait::async_trait;
use forgs::store::AppRecord;
use forgs::{AppKind, TokenHash};
use forgs_http::AppTokenLookup;

use crate::state::Db;
use crate::subject::NODE_KIND;

/// [`AppTokenLookup`] over the `node` table.
#[derive(Debug, Clone)]
pub struct NodeTokens {
    db: Db,
}

impl NodeTokens {
    /// Over `db`.
    #[must_use]
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AppTokenLookup for NodeTokens {
    async fn lookup_app(
        &self,
        kind: AppKind,
        hash: &TokenHash,
    ) -> Result<Option<AppRecord>, String> {
        if kind.label() != NODE_KIND {
            return Ok(None);
        }
        let Some((node, org, issued_at)) = self
            .db
            .node_by_token_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        // Built through the forgs constructor from the row; a row whose ids
        // do not form a valid key fails closed (unknown credential).
        let Some(subject) =
            forgs::SubjectKey::new(Some(&org.0), forgs::SubjectKind::App(NODE_KIND), &node.0)
        else {
            tracing::warn!(node = %node, "node row does not form a subject key (fails closed)");
            return Ok(None);
        };
        Ok(Some(AppRecord {
            subject,
            // A node token does not expire; it rotates.
            expires: None,
            // A negative `issued_at` cannot come from the clock; clamping
            // keeps the rotation arithmetic in unsigned space.
            issued_at: Some(u64::try_from(issued_at).unwrap_or(0)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::adopt::AdoptPolicy;

    #[tokio::test]
    async fn node_lookup_bridges_to_the_node_row() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = db.ensure_org_named("acme", 1).await.unwrap();
        let format = crate::identity::token_format();
        let kind = format.app_kind(NODE_KIND).unwrap();
        let token = format.mint(forgs::TokenKind::App(kind));
        let node = db
            .register_node_full(
                &org,
                "rpi-1",
                token.hash().as_str(),
                &[],
                None,
                AdoptPolicy::Declared,
                1234,
            )
            .await
            .unwrap();

        let lookup = NodeTokens::new(db.clone());
        let rec = lookup
            .lookup_app(kind, &token.hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.subject.ns(), Some(org.0.as_str()));
        assert_eq!(rec.subject.id(), node.0);
        assert_eq!(rec.issued_at, Some(1234));
        assert_eq!(rec.expires, None);

        let other = format.mint(forgs::TokenKind::App(kind));
        assert!(lookup
            .lookup_app(kind, &other.hash())
            .await
            .unwrap()
            .is_none());
    }
}
