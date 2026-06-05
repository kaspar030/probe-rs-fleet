//! Persistent coordinator state in `SQLite` via `sqlx`.
//!
//! Three concerns are persisted: the set of boards the coordinator has seen
//! (latest snapshot per id), the leases it has granted (with close reason), and
//! an append-only audit log. The in-memory [`fleet_core::scheduler::Scheduler`]
//! remains the source of truth for *live* lease state; this layer records
//! history and supports a future reload-on-boot (a documented v1 limitation,
//! not yet implemented).
//!
//! Queries use the runtime (`query`) API rather than the compile-time `query!`
//! macro so the crate builds without a live database.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{BoardId, LeaseId, Principal};

use crate::error::Result;

/// Embedded migrations (run on [`Db::connect`]).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// A handle to the coordinator's `SQLite` database. Cheap to clone (wraps a pool).
#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open (creating if absent) the `SQLite` database at `path` and run
    /// migrations.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] if the database cannot be
    /// opened or migrated.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    /// Open an in-memory database (for tests) and run migrations.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] if migrations fail.
    pub async fn connect_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    /// Borrow the underlying pool (for advanced callers / tests).
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Record (insert or update) a board snapshot at time `now`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn record_board(&self, board: &Board, now: i64) -> Result<()> {
        // Tags are simple identifiers (no newlines); store newline-joined.
        let tags = board.tags.join("\n");
        let state = board_state_label(&board.state);
        sqlx::query(
            "INSERT INTO boards (id, agent, chip, tags, exclusive, state, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT(id) DO UPDATE SET
                agent = excluded.agent,
                chip = excluded.chip,
                tags = excluded.tags,
                exclusive = excluded.exclusive,
                state = excluded.state,
                last_seen = excluded.last_seen",
        )
        .bind(board.id.0.as_str())
        .bind(board.agent.0.as_str())
        .bind(board.chip.as_str())
        .bind(tags)
        .bind(i64::from(board.exclusive))
        .bind(state)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a newly granted lease.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn record_lease(
        &self,
        lease: LeaseId,
        board: &BoardId,
        agent: &str,
        holder: &Principal,
        granted_at: i64,
        expires: i64,
    ) -> Result<()> {
        // `lease` ids come from a monotonic counter; the cast preserves value
        // for any realistic id count.
        let lease_i64 = i64::try_from(lease.0).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO leases (lease, board, agent, holder, granted_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(lease) DO UPDATE SET
                expires = excluded.expires,
                closed_at = NULL,
                close_reason = NULL",
        )
        .bind(lease_i64)
        .bind(board.0.as_str())
        .bind(agent)
        .bind(holder.0.as_str())
        .bind(granted_at)
        .bind(expires)
        .execute(&self.pool)
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
        sqlx::query("UPDATE leases SET expires = ?2 WHERE lease = ?1 AND closed_at IS NULL")
            .bind(lease_i64)
            .bind(expires)
            .execute(&self.pool)
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
            "UPDATE leases SET closed_at = ?2, close_reason = ?3
             WHERE lease = ?1 AND closed_at IS NULL",
        )
        .bind(lease_i64)
        .bind(closed_at)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Count currently-open (not closed) leases.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn open_lease_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM leases WHERE closed_at IS NULL")
            .fetch_one(&self.pool)
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
            "INSERT INTO audit_log (ts, principal, action, board, lease, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(entry.ts)
        .bind(entry.principal)
        .bind(entry.action)
        .bind(entry.board)
        .bind(lease)
        .bind(entry.detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Count audit-log rows (test/inspection helper).
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn audit_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }
}

/// One audit-log entry to append.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    /// Epoch-seconds timestamp.
    pub ts: i64,
    /// The acting principal, if any.
    pub principal: Option<&'a str>,
    /// A short action label, e.g. `lease.grant`.
    pub action: &'a str,
    /// The board concerned, if any.
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
    use fleet_proto::ids::AgentId;

    fn board() -> Board {
        Board {
            id: BoardId("b1".to_owned()),
            agent: AgentId("agent-a".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec!["nrf52".to_owned(), "ble".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    #[tokio::test]
    async fn migrate_and_record_board() {
        let db = Db::connect_in_memory().await.unwrap();
        db.record_board(&board(), 1000).await.unwrap();
        // Upsert: same id again with a later timestamp.
        db.record_board(&board(), 2000).await.unwrap();
        let row: (i64, i64) =
            sqlx::query_as("SELECT first_seen, last_seen FROM boards WHERE id = 'b1'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, 1000);
        assert_eq!(row.1, 2000);
    }

    #[tokio::test]
    async fn lease_lifecycle() {
        let db = Db::connect_in_memory().await.unwrap();
        let lease = LeaseId(1);
        db.record_lease(
            lease,
            &BoardId("b1".to_owned()),
            "agent-a",
            &Principal("alice".to_owned()),
            1000,
            1600,
        )
        .await
        .unwrap();
        assert_eq!(db.open_lease_count().await.unwrap(), 1);

        db.update_lease_expiry(lease, 2000).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT expires FROM leases WHERE lease = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 2000);

        db.close_lease(lease, 2100, "released").await.unwrap();
        assert_eq!(db.open_lease_count().await.unwrap(), 0);
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
        db.append_audit(&AuditEntry {
            ts: 1000,
            principal: Some("alice"),
            action: "lease.grant",
            board: Some("b1"),
            lease: Some(LeaseId(1)),
            detail: Some("interactive"),
        })
        .await
        .unwrap();
        db.append_audit(&AuditEntry {
            ts: 1001,
            principal: None,
            action: "lease.expire",
            board: Some("b1"),
            lease: Some(LeaseId(1)),
            detail: None,
        })
        .await
        .unwrap();
        assert_eq!(db.audit_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn file_backed_db_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coord.sqlite");
        let path_str = path.to_str().unwrap();
        let db = Db::connect(path_str).await.unwrap();
        db.record_board(&board(), 1000).await.unwrap();
        drop(db);
        // Reopen and confirm persistence.
        let db = Db::connect(path_str).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boards")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 1);
    }
}
