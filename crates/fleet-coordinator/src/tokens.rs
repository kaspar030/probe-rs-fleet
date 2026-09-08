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
use tracing::warn;

use fleet_auth::store::{
    AuthKeyRecord, NodeRecord, RefreshRecord, SessionRecord, TokenStore, WorkloadRecord,
};
use fleet_auth::TokenHash;
use fleet_proto::ids::SubjectKey;

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

    async fn lookup_workload(&self, hash: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
        let Some((subject, expires)) = self
            .workload_by_token_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        // The stored `subject` is a rendered `SubjectKey`, split back into its
        // namespace and id halves. A row that will not parse resolves to `None`
        // — **fails closed**, the same rule `authz::board_access` applies to an
        // unparseable grant row. Widening it into some default subject is the
        // one outcome that must never happen, since that subject would then be
        // matched against grants.
        let Some(key) = SubjectKey::parse(&subject) else {
            warn!(%subject, "dropping an unparseable workload_token row (fails closed)");
            return Ok(None);
        };
        Ok(Some(WorkloadRecord {
            org_id: key.org.0,
            id: key.id,
            expires: u64::try_from(expires).unwrap_or(0),
        }))
    }

    async fn lookup_refresh_token(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<RefreshRecord>, String> {
        let row = self
            .refresh_token_by_token_hash(hash.as_str())
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|(user, org, expires)| RefreshRecord {
            user_id: user,
            org_id: org.0,
            expires: u64::try_from(expires).unwrap_or(0),
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

    /// The refresh-token bridge, and the property the whole design rests on:
    /// looking one up **does not consume it**, so the row is still there for
    /// the next redemption. The sweep is what eventually reclaims it.
    #[tokio::test]
    async fn refresh_token_lookup_bridges_its_row_and_does_not_consume() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        db.ensure_user_member(&org, "alice", Role::Admin)
            .await
            .unwrap();

        let token = OpaqueToken::mint(TokenKind::Refresh);
        db.insert_refresh_token(token.hash().as_str(), &org, "alice", 1_000, 5_000)
            .await
            .unwrap();

        for _ in 0..3 {
            let record = db
                .lookup_refresh_token(&token.hash())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.user_id, "alice");
            assert_eq!(record.org_id, org.0);
            assert_eq!(record.expires, 5_000);
        }

        let other = OpaqueToken::mint(TokenKind::Refresh);
        assert!(db
            .lookup_refresh_token(&other.hash())
            .await
            .unwrap()
            .is_none());

        // The sweep reclaims it, and it then resolves to nothing.
        assert_eq!(
            db.delete_expired_refresh_tokens(5_000).await.unwrap(),
            1,
            "expiry is inclusive in the sweep"
        );
        assert!(db
            .lookup_refresh_token(&token.hash())
            .await
            .unwrap()
            .is_none());
    }

    /// `logout --all` deletes both credential kinds for one user, and touches
    /// nobody else's — the cross-user delete this feature must never enable.
    #[tokio::test]
    async fn deleting_a_users_credentials_is_scoped_to_that_user() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        for who in ["alice", "bob"] {
            db.ensure_user_member(&org, who, Role::Admin).await.unwrap();
            let session = OpaqueToken::mint(TokenKind::Session);
            db.insert_session(session.hash().as_str(), &org, who, 1_000, 9_000)
                .await
                .unwrap();
            let refresh = OpaqueToken::mint(TokenKind::Refresh);
            db.insert_refresh_token(refresh.hash().as_str(), &org, who, 1_000, 9_000)
                .await
                .unwrap();
        }

        assert_eq!(db.delete_sessions_for_user(&org, "alice").await.unwrap(), 1);
        assert_eq!(
            db.delete_refresh_tokens_for_user(&org, "alice")
                .await
                .unwrap(),
            1
        );

        let (sessions,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM session WHERE user_id = 'bob'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let (refreshes,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM refresh_token WHERE user_id = 'bob'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!((sessions, refreshes), (1, 1), "bob's credentials survive");
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
        assert!(db
            .consume_auth_key(key.hash().as_str(), 1_500)
            .await
            .unwrap()
            .is_some());
        assert!(db.lookup_auth_key(&key.hash()).await.unwrap().is_none());
    }

    /// The workload bridge splits the stored `SubjectKey` back into its two
    /// halves, and an id containing a slash (`owner/repo`) survives the round
    /// trip — which is the property that lets a repo be a subject id with no
    /// schema change.
    #[tokio::test]
    async fn workload_lookup_splits_the_stored_subject_key() {
        use crate::state::WorkloadClaimColumns;
        let db = Db::connect_in_memory().await.unwrap();
        let token = OpaqueToken::mint(TokenKind::Workload);
        let key = fleet_proto::ids::workload_subject_key("ariel-os/ariel-os");
        db.insert_workload_token(
            token.hash().as_str(),
            &key,
            "github_oidc",
            &WorkloadClaimColumns {
                repository: Some("ariel-os/ariel-os".to_owned()),
                repository_owner: Some("ariel-os".to_owned()),
                ..WorkloadClaimColumns::default()
            },
            1_000,
            4_600,
        )
        .await
        .unwrap();

        let record = db.lookup_workload(&token.hash()).await.unwrap().unwrap();
        assert_eq!(record.org_id, "gha");
        assert_eq!(record.id, "ariel-os/ariel-os");
        assert_eq!(record.expires, 4_600);

        // The sweep reclaims it, and it then resolves to nothing.
        assert_eq!(
            db.delete_expired_workload_tokens(4_600).await.unwrap(),
            1,
            "expiry is inclusive in the sweep"
        );
        assert!(db.lookup_workload(&token.hash()).await.unwrap().is_none());
    }

    /// A `workload_token` row whose subject no longer parses resolves to
    /// `None`, never to some default subject: a subject invented here would be
    /// matched against grants.
    #[tokio::test]
    async fn an_unparseable_workload_subject_fails_closed() {
        use crate::state::WorkloadClaimColumns;
        let db = Db::connect_in_memory().await.unwrap();
        let token = OpaqueToken::mint(TokenKind::Workload);
        // Written straight through sqlx: the typed API cannot express a broken
        // key, which is the point — this simulates a corrupt or
        // future-versioned row.
        db.insert_workload_token(
            token.hash().as_str(),
            &fleet_proto::ids::workload_subject_key("a/b"),
            "github_oidc",
            &WorkloadClaimColumns::default(),
            1_000,
            4_600,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE workload_token SET subject = 'nonsense'")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(db.lookup_workload(&token.hash()).await.unwrap().is_none());
    }

    /// The reserved namespace cannot be claimed as a tenant — at *every*
    /// org-creation path, not just through the config validator.
    #[tokio::test]
    async fn the_workload_namespace_is_not_creatable_as_an_org() {
        let db = Db::connect_in_memory().await.unwrap();
        assert!(db
            .ensure_org(&OrgId("gha".to_owned()), "team")
            .await
            .is_err());
        // …but the migration's own row exists, so the audit-log foreign key
        // holds on the paths that fall back to a workload's namespace.
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM org WHERE id = 'gha'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// Migration 0007's reserved row must not collide with a **slug** a real
    /// login could already have produced.
    ///
    /// `org.slug` is `NOT NULL UNIQUE` and the insert's `ON CONFLICT` names only
    /// the id, so a pre-existing `org(id = 'gh-<n>', slug = 'gha')` — which
    /// `unique_personal_slug` produces for a user whose GitHub login is `gha` —
    /// would abort the migration and leave the coordinator refusing to start
    /// after an upgrade. The reserved slug is therefore `system:gha`, which no
    /// login can yield because the sanitiser maps everything outside
    /// `[a-z0-9_-]` to `-`.
    #[tokio::test]
    async fn the_reserved_row_survives_a_pre_existing_gha_slug() {
        // A connection with 0001..0006 applied but not 0007 is not expressible
        // through `Db`, so the collision is staged against the finished schema
        // and the reserved row's own statement is replayed — which is exactly
        // what running the migration over such a database would do.
        let db = Db::connect_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO org (id, slug, kind, created_at) VALUES (?1, 'gha', 'personal', 1)",
        )
        .bind("gh-42")
        .execute(db.pool())
        .await
        .expect("a user whose login is `gha` may already own that slug");

        sqlx::query(
            "INSERT INTO org (id, slug, kind, created_at)
             VALUES ('gha', 'system:gha', 'system', unixepoch())
             ON CONFLICT(id) DO NOTHING",
        )
        .execute(db.pool())
        .await
        .expect("the reserved row must not collide with an existing `gha` slug");

        // Both rows coexist, and the reserved one still holds the `gha` *id*
        // the audit-log foreign key needs.
        let (kind,): (String,) = sqlx::query_as("SELECT kind FROM org WHERE id = 'gha'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(kind, "system");
        let (slug,): (String,) = sqlx::query_as("SELECT slug FROM org WHERE id = 'gh-42'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(slug, "gha", "the pre-existing row is untouched");
    }

    /// The sanitiser cannot produce the reserved slug from any login, which is
    /// what makes the collision above unrepresentable rather than merely
    /// unlikely: `:` is not in the allowed set, so every candidate it builds is
    /// `:`-free.
    #[tokio::test]
    async fn no_login_can_produce_the_reserved_slug() {
        let db = Db::connect_in_memory().await.unwrap();
        for (i, login) in [
            "system:gha",
            "system gha",
            "SYSTEM:GHA",
            "gha",
            "system-gha",
        ]
        .into_iter()
        .enumerate()
        {
            let gh_id = 1000 + i64::try_from(i).unwrap();
            let (_user, org, _created) = db
                .upsert_github_user(gh_id, login, None, 1_000)
                .await
                .unwrap();
            let (slug,): (String,) = sqlx::query_as("SELECT slug FROM org WHERE id = ?1")
                .bind(org.0.as_str())
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_ne!(
                slug, "system:gha",
                "login {login:?} reached the reserved slug"
            );
            assert!(!slug.contains(':'), "login {login:?} produced {slug:?}");
        }
    }
}
