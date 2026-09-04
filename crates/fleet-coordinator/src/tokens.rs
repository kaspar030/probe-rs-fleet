//! The coordinator's [`fleet_auth::TokenStore`] implementation.
//!
//! The bridge between `fleet-auth`'s verification logic and this crate's
//! `SQLite` handle. It exists as its own module so `fleet-auth` never learns
//! about `sqlx`, and so verification stays unit-testable in that crate against
//! an in-memory fake.
//!
//! Every method here is a lookup by **token hash**: the secrets themselves are
//! never stored.

use async_trait::async_trait;

use fleet_auth::store::{AuthKeyRecord, NodeRecord, SessionRecord, TokenStore};
use fleet_auth::TokenHash;

use crate::state::Db;

#[async_trait]
impl TokenStore for Db {
    async fn lookup_node(&self, hash: &TokenHash) -> Result<Option<NodeRecord>, String> {
        let row = self
            .node_by_token_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|(node, org, issued_at)| NodeRecord {
            node_id: node.0,
            org_id: org.0,
            // A negative `issued_at` cannot come from the clock; clamping keeps
            // the rotation arithmetic in unsigned space.
            token_issued_at: u64::try_from(issued_at).unwrap_or(0),
        }))
    }

    async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String> {
        let row = self
            .session_by_token_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|(user, org, expires)| SessionRecord {
            user_id: user,
            org_id: org.0,
            expires: u64::try_from(expires).unwrap_or(0),
        }))
    }

    async fn lookup_auth_key(&self, hash: &TokenHash) -> Result<Option<AuthKeyRecord>, String> {
        let row = self
            .auth_key_by_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|(org, tags, single_use, expires)| AuthKeyRecord {
            org_id: org.0,
            tags,
            single_use,
            expires: expires.and_then(|e| u64::try_from(e).ok()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_auth::{OpaqueToken, TokenKind};
    use fleet_proto::ids::{OrgId, Role};

    use crate::state::DEFAULT_ORG_ID;

    #[tokio::test]
    async fn node_lookup_bridges_to_the_node_row() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let token = OpaqueToken::mint(TokenKind::Node);
        let node = db
            .register_node(&org, "rpi-1", token.hash().as_str(), &[], 1_000)
            .await
            .unwrap();

        let record = db.lookup_node(&token.hash()).await.unwrap().unwrap();
        assert_eq!(record.node_id, node.0);
        assert_eq!(record.org_id, org.0);
        assert_eq!(record.token_issued_at, 1_000);

        let other = OpaqueToken::mint(TokenKind::Node);
        assert!(db.lookup_node(&other.hash()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_and_auth_key_lookups_bridge_their_rows() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        db.ensure_user_member(&org, "alice", Role::Admin)
            .await
            .unwrap();

        let session = OpaqueToken::mint(TokenKind::Session);
        db.insert_session(session.hash().as_str(), &org, "alice", 1_000, 2_000)
            .await
            .unwrap();
        let record = db.lookup_session(&session.hash()).await.unwrap().unwrap();
        assert_eq!(record.user_id, "alice");
        assert_eq!(record.expires, 2_000);

        let key = OpaqueToken::mint(TokenKind::AuthKey);
        db.insert_auth_key(
            &org,
            key.hash().as_str(),
            &["nrf52".to_owned()],
            true,
            Some(9_000),
            None,
            1_000,
        )
        .await
        .unwrap();
        let record = db.lookup_auth_key(&key.hash()).await.unwrap().unwrap();
        assert_eq!(record.org_id, org.0);
        assert_eq!(record.tags, vec!["nrf52".to_owned()]);
        assert!(record.single_use);
        assert_eq!(record.expires, Some(9_000));
    }

    /// A consumed single-use key must stop resolving, or `verify_auth_key`
    /// would report it valid right up to the atomic consume that then fails.
    #[tokio::test]
    async fn a_consumed_auth_key_no_longer_resolves() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        let key = OpaqueToken::mint(TokenKind::AuthKey);
        db.insert_auth_key(&org, key.hash().as_str(), &[], true, None, None, 1_000)
            .await
            .unwrap();
        assert!(db.consume_auth_key(key.hash().as_str(), 1_500).await.unwrap().is_some());
        assert!(db.lookup_auth_key(&key.hash()).await.unwrap().is_none());
    }
}
