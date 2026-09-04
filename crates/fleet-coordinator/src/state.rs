//! Persistent coordinator state in `SQLite` via `sqlx`.
//!
//! Three concerns are persisted: the set of boards the coordinator has seen
//! (latest snapshot per `(org, node, name)` key), the leases it has granted
//! (with close reason), and an append-only audit log. The in-memory
//! [`fleet_core::scheduler::Scheduler`] remains the source of truth for *live*
//! lease state; this layer records history and supports a future
//! reload-on-boot (a documented v1 limitation, not yet implemented).
//!
//! ## Tenant isolation is structural, not advisory
//!
//! Architecture revision 2 (§6.1) makes the fleet multi-tenant, and the org
//! boundary is a security boundary between customers. Rather than adding an
//! `org: &OrgId` parameter to each method — which a caller can pass the wrong
//! value to exactly as easily as it can forget a `WHERE` clause — every
//! org-scoped query lives on [`OrgDb`], a handle obtained from
//! [`Db::scoped`]. `OrgDb` binds its own org into every statement, so an
//! unscoped board / lease / audit query is not expressible from outside this
//! module. [`Db`] itself keeps only genuinely global operations (connect,
//! bootstrap, membership lookup, and the legacy enrollment tables, which take
//! an explicit org).
//!
//! Queries use the runtime (`query`) API rather than the compile-time `query!`
//! macro so the crate builds without a live database.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{AgentId, BoardRef, LeaseId, OrgId, Role, SubjectKey};

use crate::error::Result;

/// Embedded migrations (run on [`Db::connect`]).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// The org every subject is assigned to until GitHub login exists.
pub const DEFAULT_ORG_ID: &str = "default";

/// A handle to the coordinator's `SQLite` database. Cheap to clone (wraps a pool).
#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open (creating if absent) the `SQLite` database at `path`, run
    /// migrations, and ensure the default org exists.
    ///
    /// Foreign keys are enabled explicitly: sqlite defaults them **off**, which
    /// would silently reduce every `REFERENCES` in the schema to a comment.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] if the database cannot be
    /// opened or migrated.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        MIGRATOR.run(&pool).await?;
        let db = Self { pool };
        db.ensure_default_org().await?;
        Ok(db)
    }

    /// Open an in-memory database (for tests), run migrations, and ensure the
    /// default org exists.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] if migrations fail.
    pub async fn connect_in_memory() -> Result<Self> {
        let opts = "sqlite::memory:"
            .parse::<SqliteConnectOptions>()?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        MIGRATOR.run(&pool).await?;
        let db = Self { pool };
        db.ensure_default_org().await?;
        Ok(db)
    }

    /// Borrow the underlying pool.
    ///
    /// Deliberately `pub(crate)`: a public pool is the escape hatch that would
    /// make [`OrgDb`]'s whole construction advisory rather than structural.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Borrow the underlying pool from an integration test.
    ///
    /// Hidden and test-only in intent: production code inside this crate uses
    /// [`Db::pool`], everything else goes through [`OrgDb`].
    #[doc(hidden)]
    #[must_use]
    pub fn pool_for_test(&self) -> &SqlitePool {
        &self.pool
    }

    /// Scope this handle to one org.
    ///
    /// Every board / lease / audit query lives on the returned [`OrgDb`] and
    /// binds `org` into its `WHERE` clause, so an unscoped query cannot be
    /// written by a caller.
    #[must_use]
    pub fn scoped(&self, org: OrgId) -> OrgDb<'_> {
        OrgDb { db: self, org }
    }

    /// Idempotently create the bootstrap org.
    ///
    /// Every row needs an `org_id`, and a self-hosted deployment starts with no
    /// orgs at all, so this one exists from the first connect. It is *not* the
    /// org a connection resolves into: a node's org comes from its own row and a
    /// user's from the session token's, both established at enrollment. This is
    /// the org the interim admin verbs (`coordinator auth-key`,
    /// `coordinator user-token`) default to when the operator names none.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn ensure_default_org(&self) -> Result<OrgId> {
        let org = OrgId(DEFAULT_ORG_ID.to_owned());
        self.ensure_org(&org, "personal").await?;
        Ok(org)
    }

    /// Idempotently insert an org row.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn ensure_org(&self, org: &OrgId, kind: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO org (id, slug, kind, created_at)
             VALUES (?1, ?1, ?2, unixepoch())
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(org.0.as_str())
        .bind(kind)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Idempotently ensure `user` exists and is a member of `org` with at least
    /// `role`.
    ///
    /// Both rows are needed together: `member.user_id` references `user(id)`,
    /// so creating the membership without the user would fail the foreign key.
    ///
    /// # Errors
    ///
    /// Returns a database error if a write fails.
    pub async fn ensure_user_member(&self, org: &OrgId, user: &str, role: Role) -> Result<()> {
        self.ensure_org(org, "personal").await?;
        sqlx::query(
            "INSERT INTO user (id, personal_org_id, created_at)
             VALUES (?1, ?2, unixepoch())
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(user)
        .bind(org.0.as_str())
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO member (org_id, user_id, role)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(org_id, user_id) DO NOTHING",
        )
        .bind(org.0.as_str())
        .bind(user)
        .bind(role.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The role `user` holds in `org`, or `None` if it is not a member.
    ///
    /// The single membership question the authorization layer asks. Membership
    /// is defined for `SubjectKind::User` only (see `authz::require_role`).
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn role_of(&self, org: &OrgId, user: &str) -> Result<Option<Role>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT role FROM member WHERE org_id = ?1 AND user_id = ?2")
                .bind(org.0.as_str())
                .bind(user)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|r| Role::from_label(&r.0)))
    }

    /// Look up the node whose bearer token hashes to `token_hash`.
    ///
    /// Returns `(node id, org, token issued_at)`. The org comes from the node
    /// **row**, which is the invariant that stops a node token from being
    /// replayed into another tenant: `/agent` never consults a configured
    /// default org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn node_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AgentId, OrgId, i64)>> {
        let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, org_id, token_issued_at FROM node WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, org, issued)| (AgentId(id), OrgId(org), issued.unwrap_or(0))))
    }

    /// Replace a node's token hash, recording when it was issued.
    ///
    /// Called only *after* the node acks the rotation push, so the old token
    /// stays authoritative until the replacement is known to be on disk (see
    /// `fleet_auth::rotation`).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn set_node_token_hash(
        &self,
        node: &AgentId,
        token_hash: &str,
        issued_at: i64,
    ) -> Result<()> {
        sqlx::query("UPDATE node SET token_hash = ?2, token_issued_at = ?3 WHERE id = ?1")
            .bind(node.0.as_str())
            .bind(token_hash)
            .bind(issued_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Register (or refresh) a node in `org` and give it a token hash.
    ///
    /// Used by `POST /auth/token` when an auth key is redeemed. The node id is
    /// derived from `(org, name)` so re-running `agent init` on the same machine
    /// re-enrolls it rather than creating a duplicate.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn register_node(
        &self,
        org: &OrgId,
        name: &str,
        token_hash: &str,
        tags: &[String],
        now: i64,
    ) -> Result<AgentId> {
        let node_id = node_id_for(org, name);
        sqlx::query(
            "INSERT INTO node (id, org_id, name, tags, token_hash, token_issued_at, last_seen, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?6)
             ON CONFLICT(id) DO UPDATE SET
                tags = excluded.tags,
                token_hash = excluded.token_hash,
                token_issued_at = excluded.token_issued_at",
        )
        .bind(node_id.0.as_str())
        .bind(org.0.as_str())
        .bind(name)
        .bind(tags.join("\n"))
        .bind(token_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(node_id)
    }

    /// Delete a node row, revoking its token.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_node(&self, node: &AgentId) -> Result<()> {
        sqlx::query("DELETE FROM node WHERE id = ?1")
            .bind(node.0.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Insert a user session (stored by token hash).
    ///
    /// The caller must have provisioned the org, user and member rows first:
    /// `session.user_id REFERENCES user(id)` and foreign keys are enforced, so a
    /// session for a nonexistent user fails loudly here rather than becoming a
    /// valid token belonging to nobody.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn insert_session(
        &self,
        token_hash: &str,
        org: &OrgId,
        user: &str,
        issued_at: i64,
        expires: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO session (token_hash, org_id, user_id, issued_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(token_hash)
        .bind(org.0.as_str())
        .bind(user)
        .bind(issued_at)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up a session by its token hash: `(user id, org, expires)`.
    ///
    /// Expiry is **not** checked here; `fleet_auth::authenticate` does that, so
    /// there is exactly one place that decides what "expired" means.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, OrgId, i64)>> {
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT user_id, org_id, expires FROM session WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(user, org, expires)| (user, OrgId(org), expires)))
    }

    /// Delete a session (logout, or refresh replacing it).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_session(&self, token_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM session WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete every session that expired at or before `now`; returns the count.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_expired_sessions(&self, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM session WHERE expires <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Insert a node-enrollment auth key (stored by hash).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    // One argument per column, and the columns are the auth key's whole
    // definition; bundling them into a struct here would only move the same
    // eight fields one level down.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_auth_key(
        &self,
        org: &OrgId,
        key_hash: &str,
        tags: &[String],
        single_use: bool,
        expires: Option<i64>,
        created_by: Option<&str>,
        created_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO auth_key (key_hash, org_id, tags, single_use, expires, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(key_hash)
        .bind(org.0.as_str())
        .bind(tags.join("\n"))
        .bind(i64::from(single_use))
        .bind(expires)
        .bind(created_by)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up an auth key by hash **without** consuming it:
    /// `(org, tags, single_use, expires)`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn auth_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<(OrgId, Vec<String>, bool, Option<i64>)>> {
        let row: Option<(String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT org_id, tags, single_use, expires FROM auth_key
             WHERE key_hash = ?1 AND consumed_at IS NULL",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(org, tags, single_use, expires)| {
            (OrgId(org), split_tags(&tags), single_use != 0, expires)
        }))
    }

    /// Atomically consume an auth key: single-use + TTL, in one statement.
    ///
    /// A single-use key is marked consumed; a multi-use key is left redeemable.
    /// Doing this as one `UPDATE … RETURNING` is what makes "single use" mean
    /// single use under concurrent redemption, rather than a check followed by a
    /// racy write.
    ///
    /// Returns `(org, tags)` when the key was redeemable, `None` when it is
    /// unknown, already consumed, or expired.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn consume_auth_key(
        &self,
        key_hash: &str,
        now: i64,
    ) -> Result<Option<(OrgId, Vec<String>)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "UPDATE auth_key
             SET consumed_at = CASE WHEN single_use != 0 THEN ?2 ELSE consumed_at END
             WHERE key_hash = ?1
               AND consumed_at IS NULL
               AND (expires IS NULL OR expires > ?2)
             RETURNING org_id, tags",
        )
        .bind(key_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(org, tags)| (OrgId(org), split_tags(&tags))))
    }

    /// The org a node belongs to, if the node is known.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_of_node(&self, node: &AgentId) -> Result<Option<OrgId>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT org_id FROM node WHERE id = ?1")
            .bind(node.0.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| OrgId(r.0)))
    }

    /// Resolve a GitHub user id to `(user id, personal org)`, if known.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn user_by_github_id(&self, gh_id: i64) -> Result<Option<(String, OrgId)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT id, personal_org_id FROM user WHERE github_user_id = ?1")
                .bind(gh_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(id, org)| (id, OrgId(org))))
    }

    /// Provision (or refresh) the user behind a completed GitHub device flow,
    /// returning `(user id, personal org, created)`.
    ///
    /// # Identity is keyed off the immutable numeric id, never the login
    ///
    /// This is load-bearing, not stylistic. [`Db::ensure_org`] is `ON CONFLICT
    /// DO NOTHING`, so if a personal org were keyed by login slug then: bob
    /// renames on GitHub → alice claims the freed `bob` login → alice logs in →
    /// `ensure_org("bob")` no-ops → **alice is provisioned into bob's org** and
    /// can lease bob's boards. GitHub documents login reuse as exactly this
    /// account-takeover vector.
    ///
    /// So `user.id` and `org.id` are both `gh-<github_user_id>`; `org.slug` and
    /// `user.login` are cosmetic, refreshed on every login, and never consulted
    /// as keys. `slug` is `UNIQUE`, hence the fallback chain in
    /// [`unique_personal_slug`].
    ///
    /// The whole chain is written in one transaction, in FK order (org → user →
    /// member): `user.personal_org_id` and `member.user_id` are enforced
    /// references, and a half-provisioned user authenticates fine and then fails
    /// *every* authorization check (`authz::require_role` consults membership).
    ///
    /// # Errors
    ///
    /// Returns a database error if any write fails.
    pub async fn upsert_github_user(
        &self,
        gh_id: i64,
        login: &str,
        email: Option<&str>,
        now: i64,
    ) -> Result<(String, OrgId, bool)> {
        let user_id = format!("gh-{gh_id}");
        let org = OrgId(user_id.clone());

        let mut tx = self.pool.begin().await?;

        let existing: Option<(String, String)> =
            sqlx::query_as("SELECT id, personal_org_id FROM user WHERE github_user_id = ?1")
                .bind(gh_id)
                .fetch_optional(&mut *tx)
                .await?;

        if let Some((id, existing_org)) = existing {
            // Returning login: refresh the display columns only. Notably we do
            // NOT move the user between orgs — a rename must not relocate
            // anybody's leases.
            sqlx::query("UPDATE user SET login = ?2, email = ?3 WHERE id = ?1")
                .bind(id.as_str())
                .bind(login)
                .bind(email)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok((id, OrgId(existing_org), false));
        }

        let slug = unique_personal_slug(&mut tx, login, gh_id, &user_id).await?;
        sqlx::query(
            "INSERT INTO org (id, slug, kind, created_at)
             VALUES (?1, ?2, 'personal', ?3)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(org.0.as_str())
        .bind(slug.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO user (id, personal_org_id, github_user_id, login, email, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                github_user_id = excluded.github_user_id,
                login = excluded.login,
                email = excluded.email",
        )
        .bind(user_id.as_str())
        .bind(org.0.as_str())
        .bind(gh_id)
        .bind(login)
        .bind(email)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Everyone is always in an org; yours is an org of one (§6.1). You are
        // its admin — there is deliberately no user-owned/org-owned branch
        // anywhere, so "my own boards" is just admin in my personal org.
        sqlx::query(
            "INSERT INTO member (org_id, user_id, role)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(org_id, user_id) DO NOTHING",
        )
        .bind(org.0.as_str())
        .bind(user_id.as_str())
        .bind(Role::Admin.as_str())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((user_id, org, true))
    }

    /// The slug of an org, for display.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_slug(&self, org: &OrgId) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT slug FROM org WHERE id = ?1")
            .bind(org.0.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.0))
    }
}

/// A [`Db`] handle scoped to exactly one org.
///
/// Every method binds `self.org` into its statement, so the caller cannot
/// express a query that spans orgs — which is the point: tenant isolation is a
/// property of the type, not of reviewer vigilance.
#[derive(Debug, Clone)]
pub struct OrgDb<'a> {
    db: &'a Db,
    org: OrgId,
}

impl OrgDb<'_> {
    /// The org this handle is scoped to.
    #[must_use]
    pub fn org(&self) -> &OrgId {
        &self.org
    }

    /// Idempotently record a node in this org, refreshing `last_seen`.
    ///
    /// Boards reference `node(id)`, so this must run before any
    /// [`OrgDb::record_board`] for that node — otherwise every board insert
    /// fails the foreign key (silently, since board recording is best-effort).
    /// This is also the minimal auto-adoption stub: a node that connects and
    /// reports inventory is registered in the org it authenticated into.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn ensure_node(&self, node: &AgentId, now: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO node (id, org_id, name, last_seen, created_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
        )
        .bind(node.0.as_str())
        .bind(self.org.0.as_str())
        .bind(node.0.as_str())
        .bind(now)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Record (insert or update) a board snapshot at time `now`.
    ///
    /// The board's org must match this handle's org; a mismatch is refused
    /// rather than silently written into the wrong tenant.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails, or
    /// [`crate::error::CoordinatorError::Protocol`] on an org mismatch.
    pub async fn record_board(&self, board: &Board, now: i64) -> Result<()> {
        if board.id.org != self.org {
            return Err(crate::error::CoordinatorError::Protocol(format!(
                "board {} does not belong to org {}",
                board.id, self.org
            )));
        }
        // Tags are simple identifiers (no newlines); store newline-joined.
        let tags = board.tags.join("\n");
        let state = board_state_label(&board.state);
        sqlx::query(
            "INSERT INTO board (org_id, node_id, name, chip, tags, exclusive, state, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(org_id, node_id, name) DO UPDATE SET
                chip = excluded.chip,
                tags = excluded.tags,
                exclusive = excluded.exclusive,
                state = excluded.state,
                last_seen = excluded.last_seen",
        )
        .bind(self.org.0.as_str())
        .bind(board.id.node.0.as_str())
        .bind(board.id.name.as_str())
        .bind(board.chip.as_str())
        .bind(tags)
        .bind(i64::from(board.exclusive))
        .bind(state)
        .bind(now)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Count the boards recorded in this org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn board_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM board WHERE org_id = ?1")
            .bind(self.org.0.as_str())
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }

    /// Whether a board with this key is recorded in this org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn has_board(&self, board: &BoardRef) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM board WHERE org_id = ?1 AND node_id = ?2 AND name = ?3",
        )
        .bind(self.org.0.as_str())
        .bind(board.node.0.as_str())
        .bind(board.name.as_str())
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.is_some())
    }

    /// Record a newly granted lease.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn record_lease(
        &self,
        lease: LeaseId,
        board: &BoardRef,
        holder: &SubjectKey,
        granted_at: i64,
        expires: i64,
    ) -> Result<()> {
        // `lease` ids come from a monotonic counter; the cast preserves value
        // for any realistic id count.
        let lease_i64 = i64::try_from(lease.0).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO leases (lease, org_id, node_id, board_name, holder, granted_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(lease) DO UPDATE SET
                expires = excluded.expires,
                closed_at = NULL,
                close_reason = NULL",
        )
        .bind(lease_i64)
        .bind(self.org.0.as_str())
        .bind(board.node.0.as_str())
        .bind(board.name.as_str())
        .bind(holder.to_string())
        .bind(granted_at)
        .bind(expires)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Update an active lease's expiry.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn update_lease_expiry(&self, lease: LeaseId, expires: i64) -> Result<()> {
        let lease_i64 = i64::try_from(lease.0).unwrap_or(i64::MAX);
        sqlx::query(
            "UPDATE leases SET expires = ?3
             WHERE lease = ?1 AND org_id = ?2 AND closed_at IS NULL",
        )
        .bind(lease_i64)
        .bind(self.org.0.as_str())
        .bind(expires)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Close a lease, recording the time and reason.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn close_lease(&self, lease: LeaseId, closed_at: i64, reason: &str) -> Result<()> {
        let lease_i64 = i64::try_from(lease.0).unwrap_or(i64::MAX);
        sqlx::query(
            "UPDATE leases SET closed_at = ?3, close_reason = ?4
             WHERE lease = ?1 AND org_id = ?2 AND closed_at IS NULL",
        )
        .bind(lease_i64)
        .bind(self.org.0.as_str())
        .bind(closed_at)
        .bind(reason)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Count currently-open (not closed) leases in this org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn open_lease_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM leases WHERE org_id = ?1 AND closed_at IS NULL",
        )
        .bind(self.org.0.as_str())
        .fetch_one(self.db.pool())
        .await?;
        Ok(row.0)
    }

    /// Append a row to the audit log.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn append_audit(&self, entry: &AuditEntry<'_>) -> Result<()> {
        let lease = entry.lease.map(|l| i64::try_from(l.0).unwrap_or(i64::MAX));
        sqlx::query(
            "INSERT INTO audit_log (ts, org_id, subject, action, node_id, board, lease, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(entry.ts)
        .bind(self.org.0.as_str())
        .bind(entry.subject)
        .bind(entry.action)
        .bind(entry.node)
        .bind(entry.board)
        .bind(lease)
        .bind(entry.detail)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Count audit-log rows in this org (test/inspection helper).
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn audit_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE org_id = ?1")
            .bind(self.org.0.as_str())
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }

    /// Fetch the most recent audit-log lines for this org, newest first,
    /// optionally filtered to a single board (by node-local name), capped at
    /// `limit` rows.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn recent_audit(
        &self,
        board: Option<&str>,
        limit: i64,
    ) -> Result<Vec<fleet_proto::admin::LogLine>> {
        let rows: Vec<(i64, String, Option<String>, Option<String>)> = match board {
            Some(b) => sqlx::query_as(
                "SELECT ts, action, board, detail FROM audit_log
                 WHERE org_id = ?1 AND board = ?2 ORDER BY id DESC LIMIT ?3",
            )
            .bind(self.org.0.as_str())
            .bind(b)
            .bind(limit)
            .fetch_all(self.db.pool())
            .await?,
            None => sqlx::query_as(
                "SELECT ts, action, board, detail FROM audit_log
                 WHERE org_id = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .bind(self.org.0.as_str())
            .bind(limit)
            .fetch_all(self.db.pool())
            .await?,
        };
        Ok(rows
            .into_iter()
            .map(|(ts, action, board, detail)| fleet_proto::admin::LogLine {
                ts,
                action,
                board,
                detail,
            })
            .collect())
    }
}

/// One audit-log entry to append. The org comes from the [`OrgDb`] it is
/// appended through, so it cannot be set to another tenant's.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    /// Epoch-seconds timestamp.
    pub ts: i64,
    /// The acting subject, rendered as a `SubjectKey`, if any.
    pub subject: Option<&'a str>,
    /// A short action label, e.g. `lease.grant`.
    pub action: &'a str,
    /// The node concerned, if any.
    pub node: Option<&'a str>,
    /// The board concerned (node-local name), if any.
    pub board: Option<&'a str>,
    /// The lease concerned, if any.
    pub lease: Option<LeaseId>,
    /// Free-form detail.
    pub detail: Option<&'a str>,
}

/// Split a newline-joined tag column back into tags, dropping empties.
fn split_tags(joined: &str) -> Vec<String> {
    joined
        .split('\n')
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Choose a free `org.slug` for a personal org.
///
/// Cosmetic — nothing keys off it (see [`Db::upsert_github_user`]) — but the
/// column is `UNIQUE`, so a login already taken by an earlier account must fall
/// back rather than fail the insert. Chain: `<login>` → `<login>-<gh_id>` → the
/// org id itself, which is unique by construction.
async fn unique_personal_slug(
    tx: &mut sqlx::SqliteConnection,
    login: &str,
    gh_id: i64,
    org_id: &str,
) -> Result<String> {
    let sanitised: String = login
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // Trim the separators the map above can leave at the edges, so a login of
    // `!!` does not become the slug `--` (or, worse, make `-<gh_id>` look like a
    // deliberate name).
    let sanitised = sanitised.trim_matches('-').to_owned();
    let candidates = [
        sanitised.clone(),
        format!("{sanitised}-{gh_id}"),
        org_id.to_owned(),
    ];
    for candidate in candidates {
        if candidate.is_empty() || candidate.starts_with('-') {
            continue;
        }
        let taken: Option<(String,)> = sqlx::query_as("SELECT id FROM org WHERE slug = ?1")
            .bind(candidate.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        if taken.is_none() {
            return Ok(candidate);
        }
    }
    Ok(org_id.to_owned())
}


/// Derive a node's id from `(org, name)`.
///
/// Deterministic on purpose: re-running `agent init` on the same machine
/// re-enrolls that node (replacing its token) instead of littering the org with
/// duplicate rows for one physical Pi. The id is namespaced by org so the same
/// node name in two tenants is two nodes.
fn node_id_for(org: &OrgId, name: &str) -> AgentId {
    AgentId(format!("{}/{name}", org.0))
}


fn board_state_label(state: &BoardState) -> &'static str {
    match state {
        BoardState::Idle => "idle",
        BoardState::Leased { .. } => "leased",
        BoardState::Faulted { .. } => "faulted",
        BoardState::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::board::PowerKind;
    use fleet_proto::ids::SubjectKind;

    fn org(name: &str) -> OrgId {
        OrgId(name.to_owned())
    }

    fn board_ref(org_name: &str, node: &str, name: &str) -> BoardRef {
        BoardRef::new(org(org_name), AgentId(node.to_owned()), name)
    }

    fn board_in(org_name: &str, node: &str, name: &str) -> Board {
        Board {
            id: board_ref(org_name, node, name),
            agent: AgentId(node.to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec!["nrf52".to_owned(), "ble".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    fn holder(org_name: &str, id: &str) -> SubjectKey {
        SubjectKey {
            org: org(org_name),
            kind: SubjectKind::User,
            id: id.to_owned(),
        }
    }

    /// Prepare an org with a node so board/lease foreign keys resolve.
    async fn seeded(db: &Db, org_name: &str, node: &str) -> OrgId {
        let o = org(org_name);
        db.ensure_org(&o, "personal").await.unwrap();
        db.scoped(o.clone())
            .ensure_node(&AgentId(node.to_owned()), 1000)
            .await
            .unwrap();
        o
    }

    #[tokio::test]
    async fn default_org_is_created_on_connect() {
        let db = Db::connect_in_memory().await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM org WHERE id = 'default'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 1);
        // Idempotent.
        db.ensure_default_org().await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM org")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let db = Db::connect_in_memory().await.unwrap();
        // A board for a node that does not exist must be refused, not silently
        // accepted — this is what makes `ensure_node` load-bearing.
        let err = db
            .scoped(org(DEFAULT_ORG_ID))
            .record_board(&board_in(DEFAULT_ORG_ID, "ghost", "b1"), 1000)
            .await;
        assert!(err.is_err(), "FK must reject a board with no node row");
    }

    #[tokio::test]
    async fn ensure_node_then_record_board_persists() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        let scoped = db.scoped(o);
        scoped
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "b1"), 1000)
            .await
            .unwrap();
        // Upsert: same key again with a later timestamp.
        scoped
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "b1"), 2000)
            .await
            .unwrap();
        assert_eq!(scoped.board_count().await.unwrap(), 1);
        assert!(scoped
            .has_board(&board_ref(DEFAULT_ORG_ID, "rpi-1", "b1"))
            .await
            .unwrap());
        let row: (i64, i64) = sqlx::query_as(
            "SELECT first_seen, last_seen FROM board WHERE org_id = 'default' AND name = 'b1'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(row.0, 1000);
        assert_eq!(row.1, 2000);
    }

    #[tokio::test]
    async fn record_board_refuses_a_foreign_org_board() {
        let db = Db::connect_in_memory().await.unwrap();
        let a = seeded(&db, "org-a", "rpi-1").await;
        seeded(&db, "org-b", "rpi-2").await;
        let err = db
            .scoped(a)
            .record_board(&board_in("org-b", "rpi-2", "b1"), 1000)
            .await;
        assert!(err.is_err(), "cross-org board write must be refused");
    }

    /// The isolation the whole design exists for: two orgs' rows never leak
    /// into each other's queries.
    #[tokio::test]
    async fn org_scoping_isolates_boards_leases_and_audit() {
        let db = Db::connect_in_memory().await.unwrap();
        let a = seeded(&db, "org-a", "node-a").await;
        let b = seeded(&db, "org-b", "node-b").await;
        let (da, db_) = (db.scoped(a.clone()), db.scoped(b.clone()));

        da.record_board(&board_in("org-a", "node-a", "dk"), 1000)
            .await
            .unwrap();
        db_.record_board(&board_in("org-b", "node-b", "dk"), 1000)
            .await
            .unwrap();
        da.record_lease(
            LeaseId(1),
            &board_ref("org-a", "node-a", "dk"),
            &holder("org-a", "alice"),
            1000,
            2000,
        )
        .await
        .unwrap();
        db_.record_lease(
            LeaseId(2),
            &board_ref("org-b", "node-b", "dk"),
            &holder("org-b", "alice"),
            1000,
            2000,
        )
        .await
        .unwrap();
        da.append_audit(&AuditEntry {
            ts: 1000,
            subject: Some("org-a/user:alice"),
            action: "lease.grant",
            node: Some("node-a"),
            board: Some("dk"),
            lease: Some(LeaseId(1)),
            detail: None,
        })
        .await
        .unwrap();

        // Same board *name* in both orgs, but each side sees exactly one.
        assert_eq!(da.board_count().await.unwrap(), 1);
        assert_eq!(db_.board_count().await.unwrap(), 1);
        assert!(!db_
            .has_board(&board_ref("org-a", "node-a", "dk"))
            .await
            .unwrap());

        assert_eq!(da.open_lease_count().await.unwrap(), 1);
        assert_eq!(db_.open_lease_count().await.unwrap(), 1);
        // org B cannot close org A's lease.
        db_.close_lease(LeaseId(1), 1500, "released").await.unwrap();
        assert_eq!(da.open_lease_count().await.unwrap(), 1);
        // …but org A can.
        da.close_lease(LeaseId(1), 1500, "released").await.unwrap();
        assert_eq!(da.open_lease_count().await.unwrap(), 0);

        assert_eq!(da.audit_count().await.unwrap(), 1);
        assert_eq!(db_.audit_count().await.unwrap(), 0);
        assert!(db_.recent_audit(None, 100).await.unwrap().is_empty());
        assert_eq!(da.recent_audit(Some("dk"), 100).await.unwrap().len(), 1);
        assert!(db_.recent_audit(Some("dk"), 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_lease_expiry_is_org_scoped() {
        let db = Db::connect_in_memory().await.unwrap();
        let a = seeded(&db, "org-a", "node-a").await;
        let b = seeded(&db, "org-b", "node-b").await;
        db.scoped(a.clone())
            .record_board(&board_in("org-a", "node-a", "dk"), 1000)
            .await
            .unwrap();
        db.scoped(a.clone())
            .record_lease(
                LeaseId(1),
                &board_ref("org-a", "node-a", "dk"),
                &holder("org-a", "alice"),
                1000,
                2000,
            )
            .await
            .unwrap();
        db.scoped(b).update_lease_expiry(LeaseId(1), 9999).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT expires FROM leases WHERE lease = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 2000, "another org must not extend this lease");
        db.scoped(a).update_lease_expiry(LeaseId(1), 3000).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT expires FROM leases WHERE lease = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 3000);
    }

    #[tokio::test]
    async fn membership_roles() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        assert_eq!(db.role_of(&o, "alice").await.unwrap(), None);
        db.ensure_user_member(&o, "alice", Role::Admin).await.unwrap();
        assert_eq!(db.role_of(&o, "alice").await.unwrap(), Some(Role::Admin));
        // Idempotent; does not downgrade.
        db.ensure_user_member(&o, "alice", Role::Member).await.unwrap();
        assert_eq!(db.role_of(&o, "alice").await.unwrap(), Some(Role::Admin));
        // Membership is per org.
        db.ensure_org(&org("other"), "team").await.unwrap();
        assert_eq!(db.role_of(&org("other"), "alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn auth_key_consume_is_single_use_and_ttl_checked() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.insert_auth_key(&o, "hash-a", &["nrf52".to_owned()], true, Some(2000), Some("root"), 1000)
            .await
            .unwrap();

        let first = db.consume_auth_key("hash-a", 1500).await.unwrap();
        assert_eq!(first, Some((o.clone(), vec!["nrf52".to_owned()])));
        // Single use means single use: the second redemption finds nothing.
        assert!(db.consume_auth_key("hash-a", 1600).await.unwrap().is_none());

        // Expired.
        db.insert_auth_key(&o, "hash-b", &[], true, Some(2000), None, 1000)
            .await
            .unwrap();
        assert!(db.consume_auth_key("hash-b", 3000).await.unwrap().is_none());
        // ... and the expiry boundary is exclusive of `now == expires`.
        db.insert_auth_key(&o, "hash-c", &[], true, Some(2000), None, 1000)
            .await
            .unwrap();
        assert!(db.consume_auth_key("hash-c", 2000).await.unwrap().is_none());

        // Unknown.
        assert!(db.consume_auth_key("nope", 1500).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn multi_use_auth_key_survives_redemption() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        // A fleet-provisioning key that enrolls a rack of Pis is not single-use.
        db.insert_auth_key(&o, "hash-m", &[], false, None, None, 1000)
            .await
            .unwrap();
        assert!(db.consume_auth_key("hash-m", 1500).await.unwrap().is_some());
        assert!(db.consume_auth_key("hash-m", 1600).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn node_token_registration_lookup_and_rotation() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        assert!(db.node_by_token_hash("hash-1").await.unwrap().is_none());

        let node = db
            .register_node(&o, "rpi-lab-1", "hash-1", &["nrf52".to_owned()], 1000)
            .await
            .unwrap();
        assert_eq!(
            db.node_by_token_hash("hash-1").await.unwrap(),
            Some((node.clone(), o.clone(), 1000))
        );

        // Rotation replaces the hash: the old token stops working, the new one
        // starts. (The coordinator only calls this *after* the node acks.)
        db.set_node_token_hash(&node, "hash-2", 5000).await.unwrap();
        assert!(db.node_by_token_hash("hash-1").await.unwrap().is_none());
        assert_eq!(
            db.node_by_token_hash("hash-2").await.unwrap(),
            Some((node.clone(), o.clone(), 5000))
        );

        // Re-enrolling the same machine re-uses the row rather than duplicating
        // it, and revocation is deleting that row.
        let again = db
            .register_node(&o, "rpi-lab-1", "hash-3", &[], 6000)
            .await
            .unwrap();
        assert_eq!(again, node);
        db.delete_node(&node).await.unwrap();
        assert!(db.node_by_token_hash("hash-3").await.unwrap().is_none());
    }

    /// The same node name in two orgs is two nodes: node ids are org-namespaced,
    /// so a token minted in one tenant cannot resolve into another.
    #[tokio::test]
    async fn node_ids_are_org_namespaced() {
        let db = Db::connect_in_memory().await.unwrap();
        db.ensure_org(&org("org-a"), "team").await.unwrap();
        db.ensure_org(&org("org-b"), "team").await.unwrap();
        let a = db.register_node(&org("org-a"), "rpi", "h-a", &[], 1).await.unwrap();
        let b = db.register_node(&org("org-b"), "rpi", "h-b", &[], 1).await.unwrap();
        assert_ne!(a, b);
        assert_eq!(db.org_of_node(&a).await.unwrap(), Some(org("org-a")));
        assert_eq!(db.org_of_node(&b).await.unwrap(), Some(org("org-b")));
    }

    #[tokio::test]
    async fn session_round_trip_and_expiry_sweep() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.ensure_user_member(&o, "alice", Role::Admin).await.unwrap();

        assert!(db.session_by_token_hash("s1").await.unwrap().is_none());
        db.insert_session("s1", &o, "alice", 1000, 2000).await.unwrap();
        assert_eq!(
            db.session_by_token_hash("s1").await.unwrap(),
            Some(("alice".to_owned(), o.clone(), 2000))
        );

        db.insert_session("s2", &o, "alice", 1000, 9000).await.unwrap();
        // The sweep removes only what has actually expired.
        assert_eq!(db.delete_expired_sessions(2000).await.unwrap(), 1);
        assert!(db.session_by_token_hash("s1").await.unwrap().is_none());
        assert!(db.session_by_token_hash("s2").await.unwrap().is_some());

        db.delete_session("s2").await.unwrap();
        assert!(db.session_by_token_hash("s2").await.unwrap().is_none());
    }

    /// `session.user_id REFERENCES user(id)` with foreign keys on: a session for
    /// a user who does not exist must fail at insert, not become a valid bearer
    /// token belonging to nobody.
    #[tokio::test]
    async fn session_for_an_unknown_user_is_refused() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        assert!(db.insert_session("s1", &o, "ghost", 1000, 2000).await.is_err());
    }

    /// First login creates the user, its personal org and the admin membership;
    /// a second login reuses all three.
    #[tokio::test]
    async fn first_github_login_provisions_a_personal_org_and_is_idempotent() {
        let db = Db::connect_in_memory().await.unwrap();

        let (user, personal, created) = db
            .upsert_github_user(4242, "kaspar", Some("k@example.com"), 1_000)
            .await
            .unwrap();
        assert!(created);
        assert_eq!(user, "gh-4242");
        assert_eq!(personal, OrgId("gh-4242".to_owned()));
        assert_eq!(db.org_slug(&personal).await.unwrap().as_deref(), Some("kaspar"));
        // Admin of your own org-of-one: there is no user-owned branch, so this
        // membership is what makes "my boards" expressible at all.
        assert_eq!(
            db.role_of(&personal, &user).await.unwrap(),
            Some(Role::Admin)
        );

        let (user2, personal2, created2) = db
            .upsert_github_user(4242, "kaspar", None, 2_000)
            .await
            .unwrap();
        assert!(!created2);
        assert_eq!((user2, personal2), (user, personal));
        let orgs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM org WHERE kind = 'personal' AND id LIKE 'gh-%'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(orgs.0, 1);
    }

    /// The regression test this whole design exists for: a **renamed** login
    /// still resolves to the same user and org, and the person who later takes
    /// the freed login gets their own org rather than inheriting the first
    /// one's. Keying identity off the login name is a documented GitHub
    /// account-takeover vector.
    #[tokio::test]
    async fn a_renamed_login_cannot_be_used_to_take_over_an_org() {
        let db = Db::connect_in_memory().await.unwrap();

        let (bob, bob_org, _) = db.upsert_github_user(1, "bob", None, 1_000).await.unwrap();

        // bob renames to `bob-old` on GitHub; same numeric id.
        let (bob_again, bob_org_again, created) =
            db.upsert_github_user(1, "bob-old", None, 1_100).await.unwrap();
        assert!(!created);
        assert_eq!((bob_again, bob_org_again.clone()), (bob.clone(), bob_org.clone()));

        // alice now claims the freed `bob` login. Different numeric id, so a
        // different user and a different org — and a distinct slug, since
        // `org.slug` is UNIQUE and bob's row still holds `bob`.
        let (alice, alice_org, created) =
            db.upsert_github_user(2, "bob", None, 1_200).await.unwrap();
        assert!(created);
        assert_ne!(alice, bob);
        assert_ne!(alice_org, bob_org);
        assert_eq!(db.org_slug(&alice_org).await.unwrap().as_deref(), Some("bob-2"));
        // alice is not a member of bob's org.
        assert_eq!(db.role_of(&bob_org, &alice).await.unwrap(), None);
    }

    #[tokio::test]
    async fn github_user_lookup_and_session_minting() {
        let db = Db::connect_in_memory().await.unwrap();
        assert!(db.user_by_github_id(77).await.unwrap().is_none());
        let (user, personal, _) = db.upsert_github_user(77, "zoe", None, 1_000).await.unwrap();
        assert_eq!(
            db.user_by_github_id(77).await.unwrap(),
            Some((user.clone(), personal.clone()))
        );
        // The user row exists, so a session FK-references it successfully.
        db.insert_session("h1", &personal, &user, 1_000, 2_000)
            .await
            .unwrap();
    }

    /// A login made entirely of characters the slug sanitiser strips must still
    /// produce a usable (unique) slug rather than an empty one.
    #[tokio::test]
    async fn an_unsluggable_login_falls_back_to_the_org_id() {
        let db = Db::connect_in_memory().await.unwrap();
        let (_, personal, _) = db.upsert_github_user(9, "", None, 1_000).await.unwrap();
        assert_eq!(db.org_slug(&personal).await.unwrap().as_deref(), Some("gh-9"));
    }

    #[tokio::test]
    async fn node_org_lookup() {
        let db = Db::connect_in_memory().await.unwrap();
        let node = AgentId("rpi-1".to_owned());
        assert!(db.org_of_node(&node).await.unwrap().is_none());
        seeded(&db, "org-a", "rpi-1").await;
        assert_eq!(db.org_of_node(&node).await.unwrap(), Some(org("org-a")));
    }

    #[tokio::test]
    async fn lease_lifecycle() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        let scoped = db.scoped(o);
        scoped
            .record_board(&board_in(DEFAULT_ORG_ID, "agent-a", "b1"), 1000)
            .await
            .unwrap();
        let lease = LeaseId(1);
        scoped
            .record_lease(
                lease,
                &board_ref(DEFAULT_ORG_ID, "agent-a", "b1"),
                &holder(DEFAULT_ORG_ID, "alice"),
                1000,
                1600,
            )
            .await
            .unwrap();
        assert_eq!(scoped.open_lease_count().await.unwrap(), 1);

        scoped.update_lease_expiry(lease, 2000).await.unwrap();
        let row: (i64, String) =
            sqlx::query_as("SELECT expires, holder FROM leases WHERE lease = 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, 2000);
        assert_eq!(row.1, "default/user:alice");

        scoped.close_lease(lease, 2100, "released").await.unwrap();
        assert_eq!(scoped.open_lease_count().await.unwrap(), 0);
        let row: (Option<i64>, Option<String>) =
            sqlx::query_as("SELECT closed_at, close_reason FROM leases WHERE lease = 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, Some(2100));
        assert_eq!(row.1.as_deref(), Some("released"));
    }

    #[tokio::test]
    async fn audit_append() {
        let db = Db::connect_in_memory().await.unwrap();
        let scoped = db.scoped(org(DEFAULT_ORG_ID));
        scoped
            .append_audit(&AuditEntry {
                ts: 1000,
                subject: Some("default/user:alice"),
                action: "lease.grant",
                node: Some("agent-a"),
                board: Some("b1"),
                lease: Some(LeaseId(1)),
                detail: Some("interactive"),
            })
            .await
            .unwrap();
        scoped
            .append_audit(&AuditEntry {
                ts: 1001,
                subject: None,
                action: "lease.expire",
                node: Some("agent-a"),
                board: Some("b1"),
                lease: Some(LeaseId(1)),
                detail: None,
            })
            .await
            .unwrap();
        assert_eq!(scoped.audit_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn file_backed_db_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coord.sqlite");
        let path_str = path.to_str().unwrap();
        let db = Db::connect(path_str).await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.scoped(o.clone())
            .record_board(&board_in(DEFAULT_ORG_ID, "agent-a", "b1"), 1000)
            .await
            .unwrap();
        drop(db);
        // Reopen and confirm persistence.
        let db = Db::connect(path_str).await.unwrap();
        assert_eq!(db.scoped(o).board_count().await.unwrap(), 1);
    }
}
