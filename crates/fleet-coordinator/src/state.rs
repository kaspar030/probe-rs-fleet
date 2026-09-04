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

    /// Idempotently create the single-user bootstrap: the default org.
    ///
    /// There is exactly one user and no deployment, but every row now needs an
    /// `org_id`, so the mTLS resolution seam assigns every subject to this org
    /// until GitHub login exists. The matching `user` + `member` rows are
    /// created lazily by [`Db::ensure_user_member`] when a subject first
    /// connects, because their id is the certificate CN and is not known here.
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

    /// Insert a one-time bootstrap enrollment secret (stored by hash), scoped
    /// to `org`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn insert_enroll_token(
        &self,
        org: &OrgId,
        secret_hash: &str,
        principal: &str,
        kind: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO enroll_tokens (secret_hash, org_id, principal, kind, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(secret_hash)
        .bind(org.0.as_str())
        .bind(principal)
        .bind(kind)
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume a bootstrap enrollment secret: single-use + TTL.
    ///
    /// Marks the matching, not-yet-consumed, not-yet-expired secret as consumed
    /// at `now` and returns its `(org, principal, kind)`. Returns `None` when
    /// the secret is unknown, already consumed (reuse), or expired.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn consume_enroll_token(
        &self,
        secret_hash: &str,
        now: i64,
    ) -> Result<Option<(OrgId, String, String)>> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "UPDATE enroll_tokens SET consumed_at = ?2
             WHERE secret_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2
             RETURNING org_id, principal, kind",
        )
        .bind(secret_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(org, principal, kind)| (OrgId(org), principal, kind)))
    }

    /// Record an agent pin (issued-cert fingerprint -> agent id) in `org`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn insert_agent_pin(
        &self,
        org: &OrgId,
        fingerprint: &str,
        agent_id: &str,
        created_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO agent_pins (fingerprint, org_id, agent_id, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(fingerprint) DO UPDATE SET
                org_id = excluded.org_id,
                agent_id = excluded.agent_id",
        )
        .bind(fingerprint)
        .bind(org.0.as_str())
        .bind(agent_id)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up the `(org, agent id)` pinned to a given cert fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn agent_pin_for_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<(OrgId, AgentId)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT org_id, agent_id FROM agent_pins WHERE fingerprint = ?1")
                .bind(fingerprint)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(org, agent)| (OrgId(org), AgentId(agent))))
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
    async fn enroll_token_consume_single_use_and_ttl() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        // valid -> consumed once
        db.insert_enroll_token(&o, "hash-a", "rpi-1", "agent", 1000, 2000)
            .await
            .unwrap();
        let first = db.consume_enroll_token("hash-a", 1500).await.unwrap();
        assert_eq!(
            first,
            Some((o.clone(), "rpi-1".to_owned(), "agent".to_owned()))
        );
        // reuse rejected
        assert!(db.consume_enroll_token("hash-a", 1600).await.unwrap().is_none());

        // expired rejected
        db.insert_enroll_token(&o, "hash-b", "alice", "client", 1000, 2000)
            .await
            .unwrap();
        assert!(db.consume_enroll_token("hash-b", 3000).await.unwrap().is_none());

        // unknown rejected
        assert!(db.consume_enroll_token("nope", 1500).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn agent_pin_round_trip() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        assert!(db.agent_pin_for_fingerprint("fp1").await.unwrap().is_none());
        db.insert_agent_pin(&o, "fp1", "rpi-1", 1000).await.unwrap();
        assert_eq!(
            db.agent_pin_for_fingerprint("fp1").await.unwrap(),
            Some((o, AgentId("rpi-1".to_owned())))
        );
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
