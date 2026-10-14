//! Persistent coordinator state in `SQLite` via `sqlx`, sharing one database
//! file with forgs.
//!
//! Identity — users, orgs, memberships, sessions, API keys, grants, pending
//! approvals and identity audit — is **forgs'** (`forgs_*` tables, reached
//! through [`Db::forgs`]). What fleet persists itself is what only fleet knows
//! about: the nodes each org enrolled, the boards they declare, the leases the
//! coordinator granted (with close reason), and an append-only board / node /
//! lease audit log. The in-memory [`probefleet_core::scheduler::Scheduler`] remains
//! the source of truth for *live* lease state; this layer records history.
//!
//! An org is a forgs namespace node of kind [`crate::subject::ORG_KIND`]; an
//! [`OrgId`] carries its id, and every fleet row references
//! `forgs_ns_node(id)` with a real foreign key.
//!
//! ## Tenant isolation is structural, not advisory
//!
//! The org boundary is a security boundary between customers. Rather than
//! adding an `org: &OrgId` parameter to each method — which a caller can pass
//! the wrong value to exactly as easily as it can forget a `WHERE` clause —
//! every org-scoped query lives on [`OrgDb`], a handle obtained from
//! [`Db::scoped`]. `OrgDb` binds its own org into every statement, so an
//! unscoped board / lease / audit query is not expressible from outside this
//! module. forgs applies the same rule to its own tables (`NsScope`).
//! [`Db`] itself keeps only genuinely global operations: connect, bootstrap,
//! and node lookups keyed by something the caller cannot choose (a token
//! hash, a node id minted by [`node_id_for`]).
//!
//! Queries use the runtime (`query`) API rather than the compile-time `query!`
//! macro so the crate builds without a live database.
//!
//! ## What the `board` table means
//!
//! The `board` table is **what each node currently declares**, and the
//! in-memory scheduler is **what can be leased right now**. They are
//! deliberately not the same set:
//!
//! * A row exists iff the node's latest inventory report carries the board and
//!   the coordinator admits it — a *declared* board with any presence, or an
//!   *adopted* board the node's [`AdoptPolicy`] admits **online**.
//! * A declared board reported `Offline` keeps its row (a J-Link unplugged for
//!   an afternoon must not vanish from the UI, nor churn rows every
//!   `discovery_secs`) but leaves the scheduler: it cannot be leased.
//! * A board **absent** from the latest report — renamed, or deleted from
//!   `boards.toml` — is no longer declared, so its row is deleted
//!   ([`OrgDb::prune_boards`]) and its scheduler entry removed.
//! * An adopted board reported `Offline` is a *tombstone*, not a declaration:
//!   it is dropped from both stores whatever the policy says.
//!
//! The invariant that falls out: **the DB set is the scheduler set plus
//! declared-but-offline boards, and nothing else.** The write side of this rule
//! lives in [`crate::core::Coordinator::reconcile_inventory`].

use sqlx::sqlite::{SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

use forgs::schema::NameOrigin;
use forgs::{KindSpec, NsNodeId, RoleLadder, Schema, UserId};
use forgs_store::Store;

use probefleet_core::access::GrantScope;
use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::board::{Board, BoardState};
use probefleet_proto::ids::{BoardRef, LeaseId, NodeId, OrgId, SubjectKey};
use probefleet_proto::node_api::BoardPresence;
use probefleet_proto::token::AllowedOp;

use crate::error::{CoordinatorError, Result};
use crate::subject::{FleetRole, NODE_KIND, ORG_KIND};

/// Embedded fleet migrations (run on connect, **after** forgs' own).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Root names no org (and hence no username, since personal orgs share the
/// root name space) may take: the coordinator's own path prefixes, the
/// reserved `gha` workload namespace, and a few operator-confusing words.
///
/// Also the guard on the web UI's `/<org>/<page>` routes (`assets.rs`): a
/// reserved word is never served as an org page, so a fixed top-level route
/// cannot be shadowed. **Every new top-level route prefix must be added
/// here**; `tests/ui_assets.rs` checks the coordinator's prefixes against it.
/// Adding a word an existing org already uses would orphan that org
/// (`resolve_org` refuses reserved names), so check first.
pub const RESERVED_NAMES: &[&str] = &[
    "gha", "api", "auth", "ui", "admin", "login", "system", "node", "agent", "client", "delegate",
    "healthz",
];

/// fleet's namespace schema: one root kind, `org`, of which every user gets a
/// personal one (named as their username).
///
/// # Panics
///
/// Never: the schema is a constant the unit tests build.
#[must_use]
pub fn fleet_schema() -> Schema {
    Schema::builder()
        .kind(ORG_KIND, KindSpec::root().personal_for_users())
        .reserved(RESERVED_NAMES)
        .build()
        .expect("fleet's schema is valid")
}

/// fleet's role ladder, `member < admin` (see [`FleetRole`]).
///
/// # Panics
///
/// Never: the ladder is a constant the unit tests build.
#[must_use]
pub fn fleet_roles() -> RoleLadder {
    RoleLadder::new(&FleetRole::LADDER).expect("fleet's ladder is valid")
}

/// One `node` row as `SQLite` hands it back to [`OrgDb::list_nodes`].
type NodeDbRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    Option<i64>,
    i64,
);

/// A handle to the coordinator's `SQLite` database: forgs' store plus fleet's
/// tables in the same file. Cheap to clone (wraps a pool).
#[derive(Debug, Clone)]
pub struct Db {
    store: Store,
}

impl Db {
    /// Open (creating if absent) the database at `path` in WAL mode with
    /// foreign keys **on**, run forgs' migrations and then fleet's.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] if the database cannot be opened or
    /// migrated.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = forgs_store::connect_options(&format!("sqlite://{path}"))?
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        Self::from_pool(pool).await
    }

    /// An in-memory database (tests), migrated. One connection that is never
    /// recycled: every connection to `sqlite::memory:` is a separate database.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] if migrations fail.
    pub async fn connect_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None::<std::time::Duration>)
            .max_lifetime(None::<std::time::Duration>)
            .connect_with(forgs_store::connect_options("sqlite::memory:")?)
            .await?;
        Self::from_pool(pool).await
    }

    async fn from_pool(pool: SqlitePool) -> Result<Self> {
        let store = Store::new(pool, fleet_schema(), fleet_roles())
            .await?
            .with_app_subject_kinds(&[NODE_KIND]);
        MIGRATOR.run(store.pool()).await?;
        Ok(Self { store })
    }

    /// The forgs store: users, orgs, memberships, credentials, grants.
    #[must_use]
    pub fn forgs(&self) -> &Store {
        &self.store
    }

    /// Borrow the underlying pool.
    ///
    /// Deliberately `pub(crate)`: a public pool is the escape hatch that would
    /// make [`OrgDb`]'s whole construction advisory rather than structural.
    pub(crate) fn pool(&self) -> &SqlitePool {
        self.store.pool()
    }

    /// Borrow the underlying pool from an integration test.
    #[doc(hidden)]
    #[must_use]
    pub fn pool_for_test(&self) -> &SqlitePool {
        self.store.pool()
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

    /// Ensure a root org named `name` exists, returning its id.
    ///
    /// The deployment's shared org (`default_org` in the config): the org
    /// the interim admin verbs default to when the operator names none. It
    /// is created as an ordinary team org with no members — an operator adds
    /// them (`coordinator org …`, or `user-token --org`). The name goes
    /// through forgs' naming rules and reserved list like any other org.
    ///
    /// # Errors
    ///
    /// A store error if `name` is invalid or reserved, or the write fails.
    pub async fn ensure_org_named(&self, name: &str, now: u64) -> Result<OrgId> {
        if let Some(n) = self.store.node_by_path(&[name]).await? {
            if n.kind != ORG_KIND {
                return Err(CoordinatorError::Config(format!(
                    "`{name}` exists but is not an org"
                )));
            }
            return Ok(crate::subject::org_of(n.id));
        }
        let id = self
            .store
            .create_node(None, ORG_KIND, name, NameOrigin::App, None, now)
            .await?;
        Ok(crate::subject::org_of(id))
    }

    /// Resolve an org reference — a namespace id or a path (its name) — to
    /// the org, if it exists and is an org.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn resolve_org(&self, raw: &str) -> Result<Option<OrgId>> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        if let Ok(id) = NsNodeId::parse(raw) {
            if let Some(n) = self.store.node(id).await? {
                return Ok((n.kind == ORG_KIND).then(|| crate::subject::org_of(n.id)));
            }
        }
        let segs: Vec<&str> = raw.trim_matches('/').split('/').collect();
        match self.store.node_by_path(&segs).await {
            Ok(Some(n)) if n.kind == ORG_KIND => Ok(Some(crate::subject::org_of(n.id))),
            Ok(_) | Err(forgs_store::StoreError::Name(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// An org's display name (its path), if it exists.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn org_name(&self, org: &OrgId) -> Result<Option<String>> {
        let Some(ns) = crate::subject::ns_of(org) else {
            return Ok(None);
        };
        Ok(self.store.node(ns).await?.map(|n| n.name))
    }

    /// The personal org of `user`.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn personal_org(&self, user: UserId) -> Result<Option<OrgId>> {
        Ok(self
            .store
            .user_by_id(user)
            .await?
            .and_then(|u| u.personal_ns)
            .map(crate::subject::org_of))
    }

    /// The role `user` holds in `org` (effective, i.e. inherited down the
    /// tree), as a fleet role. `None` for a non-member, an unknown org or a
    /// label fleet does not know (fail closed).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn role_of(&self, org: &OrgId, user: UserId) -> Result<Option<FleetRole>> {
        let Some(ns) = crate::subject::ns_of(org) else {
            return Ok(None);
        };
        let role = self
            .store
            .effective_role(ns, &forgs::SubjectKey::user(user))
            .await?;
        Ok(role.and_then(|r| FleetRole::of(r, self.store.roles())))
    }

    /// Every org `user` is a direct member of.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn orgs_of_user(&self, user: UserId) -> Result<Vec<(OrgId, FleetRole)>> {
        Ok(self
            .store
            .memberships_of_user(user)
            .await?
            .into_iter()
            .filter_map(|m| {
                FleetRole::of(m.role, self.store.roles()).map(|r| (crate::subject::org_of(m.ns), r))
            })
            .collect())
    }

    /// Make `user` a member of `org` with `role` (insert or change).
    ///
    /// # Errors
    ///
    /// A store error (unknown org or user, …).
    pub async fn set_member(
        &self,
        org: &OrgId,
        user: UserId,
        role: FleetRole,
        now: u64,
    ) -> Result<()> {
        let ns = crate::subject::ns_of(org)
            .ok_or_else(|| CoordinatorError::State(format!("`{org}` is not an org id")))?;
        self.store
            .scoped(ns)
            .set_member(
                &forgs::SubjectKey::user(user),
                role.on(self.store.roles()),
                now,
            )
            .await?;
        Ok(())
    }

    /// Create a root team org named `name` and make `admin` its admin — one
    /// transaction ([`forgs_store::Store::create_node_with_admin`]).
    ///
    /// The org's `owner_user_id` is `admin`, which is what
    /// [`Db::count_orgs_owned_by`] counts. With `max_owned = Some(cap)` the
    /// creation is refused ([`forgs_store::StoreError::OwnedLimit`]) once
    /// `admin` already owns `cap` team orgs: a hard cap, checked inside the
    /// creating transaction.
    ///
    /// # Errors
    ///
    /// A store error: an invalid or reserved name ([`forgs_store::StoreError::Name`]),
    /// a taken or tombstoned one, the cap, or a write failure.
    pub async fn create_team_org(
        &self,
        name: &str,
        admin: UserId,
        origin: NameOrigin,
        max_owned: Option<u64>,
        now: u64,
    ) -> Result<OrgId> {
        let ns = self
            .store
            .create_node_with_admin(None, ORG_KIND, name, origin, admin, max_owned, now)
            .await?;
        Ok(crate::subject::org_of(ns))
    }

    /// Whether `org` is some user's personal org (which follows the username
    /// and can be neither renamed nor deleted as an org).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn is_personal_org(&self, org: &OrgId) -> Result<bool> {
        let Some(ns) = crate::subject::ns_of(org) else {
            return Ok(false);
        };
        Ok(self
            .store
            .node(ns)
            .await?
            .is_some_and(|n| n.personal_of.is_some()))
    }

    /// Prepare `org` for deletion: refuse while it still has hardware or
    /// live leases, otherwise purge its fleet **history** — closed leases and
    /// the fleet audit log — which would otherwise block the namespace delete
    /// forever (`ON DELETE RESTRICT` on `forgs_ns_node`).
    ///
    /// Returns `false`, writing nothing, while any `node`, `board` or open
    /// lease row references the org. One transaction.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn clear_org_history(&self, org: &OrgId) -> Result<bool> {
        let Some(ns) = crate::subject::ns_of(org) else {
            return Ok(false);
        };
        let ns = ns.to_string();
        let mut tx = self.pool().begin().await?;
        let (busy,): (i64,) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM node WHERE ns_node_id = ?1) \
                  + (SELECT COUNT(*) FROM board WHERE ns_node_id = ?1) \
                  + (SELECT COUNT(*) FROM leases WHERE ns_node_id = ?1 AND closed_at IS NULL)",
        )
        .bind(&ns)
        .fetch_one(&mut *tx)
        .await?;
        if busy > 0 {
            return Ok(false);
        }
        sqlx::query("DELETE FROM leases WHERE ns_node_id = ?1")
            .bind(&ns)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM audit_log WHERE ns_node_id = ?1")
            .bind(&ns)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// How many team orgs `user` created (root orgs they own that are not
    /// their personal org).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn count_orgs_owned_by(&self, user: UserId) -> Result<u64> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forgs_ns_node \
             WHERE parent_id IS NULL AND kind = ?1 AND owner_user_id = ?2 \
               AND personal_of_user_id IS NULL",
        )
        .bind(ORG_KIND)
        .bind(user.to_string())
        .fetch_one(self.pool())
        .await?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Every member of `org`, with username and role.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list_members(&self, org: &OrgId) -> Result<Vec<MemberRow>> {
        let Some(ns) = crate::subject::ns_of(org) else {
            return Ok(Vec::new());
        };
        Ok(self
            .store
            .scoped(ns)
            .list_members()
            .await?
            .into_iter()
            .filter_map(|m| {
                Some(MemberRow {
                    user_id: m.user_id?,
                    username: m.username,
                    // An unknown label is `Member`, the *lesser*: this is a
                    // listing, and a display that guessed `admin` would be
                    // the one guess with a consequence.
                    role: FleetRole::of(m.role, self.store.roles()).unwrap_or(FleetRole::Member),
                })
            })
            .collect())
    }

    /// The live grants issued to `subject`, from any org, as evaluable
    /// scopes. Rows that do not parse are dropped **closed** (and logged).
    ///
    /// The single read that crosses orgs on purpose: a grant's whole purpose
    /// is to cross an org boundary. It is scoped by the authenticated subject
    /// instead, which the caller cannot choose.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn grant_scopes_for(
        &self,
        subject: &SubjectKey,
        now: u64,
    ) -> Result<Vec<GrantScope>> {
        let Some(key) = crate::subject::to_forgs(subject) else {
            return Ok(Vec::new());
        };
        let rows = self.store.grants_for_subject(&key, now).await?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                let scope = grant_scope(row);
                if scope.is_none() {
                    tracing::warn!(
                        grant = %row.id,
                        selector = %row.selector,
                        ops = %row.ops,
                        "dropping an unparseable grant row (fails closed)"
                    );
                }
                scope
            })
            .collect())
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
    ) -> Result<Option<(NodeId, OrgId, i64)>> {
        let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, ns_node_id, token_issued_at FROM node WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|(id, org, issued)| (NodeId(id), OrgId(org), issued.unwrap_or(0))))
    }

    /// Replace a node's token hash, recording when it was issued.
    ///
    /// Called only *after* the node acks the rotation push, so the old token
    /// stays authoritative until the replacement is known to be on disk (see
    /// `forgs::rotation`).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn set_node_token_hash(
        &self,
        node: &NodeId,
        token_hash: &str,
        issued_at: i64,
    ) -> Result<()> {
        sqlx::query("UPDATE node SET token_hash = ?2, token_issued_at = ?3 WHERE id = ?1")
            .bind(node.0.as_str())
            .bind(token_hash)
            .bind(issued_at)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Register (or refresh) a node in `org` and give it a token hash.
    ///
    /// The API-key path (`POST /node/enroll`): the
    /// node has no owning user and its adoption policy is the conservative
    /// `declared`. See [`Db::register_node_full`] for the session-based
    /// (`share`) path.
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
    ) -> Result<NodeId> {
        self.register_node_full(
            org,
            name,
            token_hash,
            tags,
            None,
            AdoptPolicy::Declared,
            now,
        )
        .await
    }

    /// Register (or refresh) a node, recording its owner and adoption policy.
    ///
    /// The node id is derived from `(org, name)` so re-running `share` /
    /// `node up` on the same machine re-enrolls it rather than creating a
    /// duplicate.
    ///
    /// `ON CONFLICT` **does** overwrite `owner_user_id` and `adopt_policy`: a
    /// machine first enrolled with an auth key and later shared by its owner
    /// (or vice versa) must converge on what the latest registration asked
    /// for, rather than keeping a stale policy nobody can see. Note the
    /// contrast with [`OrgDb::ensure_node`], which runs on every inventory
    /// report and therefore must *not* touch either column.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    // One argument per column, and the columns are the node's whole
    // registration; bundling them into a struct here would only move the same
    // eight fields one level down (the same reasoning as `insert_auth_key`).
    #[allow(clippy::too_many_arguments)]
    pub async fn register_node_full(
        &self,
        org: &OrgId,
        name: &str,
        token_hash: &str,
        tags: &[String],
        owner_user_id: Option<UserId>,
        adopt: AdoptPolicy,
        now: i64,
    ) -> Result<NodeId> {
        let node_id = node_id_for(org, name);
        sqlx::query(
            "INSERT INTO node (id, ns_node_id, owner_user_id, name, tags, token_hash, token_issued_at, adopt_policy, last_seen, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?7)
             ON CONFLICT(id) DO UPDATE SET
                owner_user_id = excluded.owner_user_id,
                tags = excluded.tags,
                token_hash = excluded.token_hash,
                token_issued_at = excluded.token_issued_at,
                adopt_policy = excluded.adopt_policy",
        )
        .bind(node_id.0.as_str())
        .bind(org.0.as_str())
        .bind(owner_user_id.map(|u| u.to_string()))
        .bind(name)
        .bind(tags.join("\n"))
        .bind(token_hash)
        .bind(now)
        .bind(adopt.as_str())
        .execute(self.pool())
        .await?;
        Ok(node_id)
    }

    /// Delete a node row, revoking its token.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_node(&self, node: &NodeId) -> Result<()> {
        sqlx::query("DELETE FROM node WHERE id = ?1")
            .bind(node.0.as_str())
            .execute(self.pool())
            .await?;
        Ok(())
    }
    /// The id of the node named `name` in `org`, if one exists.
    ///
    /// Used by the interactive-approval path to refuse an approval that would
    /// silently re-credential (and thereby take over) an existing node: the
    /// requesting machine chose its own name before any org was known, so the
    /// collision cannot be detected any earlier than approval.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn node_id_in_org_by_name(&self, org: &OrgId, name: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM node WHERE ns_node_id = ?1 AND name = ?2")
                .bind(org.0.as_str())
                .bind(name)
                .fetch_optional(self.pool())
                .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Move the node named `name` from org `from` to org `to`, re-keying its
    /// `node` row and every `board` row in one transaction. Returns the new
    /// node id, [`NodeMove::NotFound`] if `from` has no such node, or
    /// [`NodeMove::NameTaken`] if `to` already has one by that name (a
    /// concurrent enroll the caller's pre-check could not see).
    ///
    /// A [`Db`] method rather than an [`OrgDb`] one **on purpose**: it is the
    /// one write that deliberately spans two orgs, and an `OrgDb` is bound to
    /// exactly one. The caller
    /// ([`crate::core::Coordinator::move_node_core`]) authorizes against both.
    ///
    /// The node id embeds the org (`node_id_for`), so the primary key itself
    /// changes. `board.node_id` is an enforced foreign key with no `ON
    /// UPDATE` action, so the check is deferred to commit
    /// (`PRAGMA defer_foreign_keys`, on the transaction's own connection),
    /// by which time both tables agree again. The token hash stays on the
    /// row, so the node's existing token authenticates the moved node.
    ///
    /// Closed `leases` and `audit_log` rows are left alone: history stays
    /// with the org it happened in.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn move_node(&self, from: &OrgId, name: &str, to: &OrgId) -> Result<NodeMove> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await?;
        let Some((old,)): Option<(String,)> =
            sqlx::query_as("SELECT id FROM node WHERE ns_node_id = ?1 AND name = ?2")
                .bind(from.0.as_str())
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(NodeMove::NotFound);
        };
        let new = node_id_for(to, name);
        let updated = sqlx::query("UPDATE node SET id = ?1, ns_node_id = ?2 WHERE id = ?3")
            .bind(new.0.as_str())
            .bind(to.0.as_str())
            .bind(old.as_str())
            .execute(&mut *tx)
            .await;
        match updated {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Ok(NodeMove::NameTaken);
            }
            Err(e) => return Err(e.into()),
        }
        sqlx::query("UPDATE board SET node_id = ?1, ns_node_id = ?2 WHERE node_id = ?3")
            .bind(new.0.as_str())
            .bind(to.0.as_str())
            .bind(old.as_str())
            .execute(&mut *tx)
            .await?;
        // UI-set board tags travel with their boards (same deferred-FK
        // reasoning as `board`).
        sqlx::query(
            "UPDATE board_tag_override SET node_id = ?1, ns_node_id = ?2 WHERE node_id = ?3",
        )
        .bind(new.0.as_str())
        .bind(to.0.as_str())
        .bind(old.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(NodeMove::Moved(new))
    }

    /// The org a node belongs to, if the node is known.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_of_node(&self, node: &NodeId) -> Result<Option<OrgId>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT ns_node_id FROM node WHERE id = ?1")
            .bind(node.0.as_str())
            .fetch_optional(self.pool())
            .await?;
        Ok(row.map(|r| OrgId(r.0)))
    }

    /// The user id that owns a node, if any.
    ///
    /// `Some` for a node created by `share` (the machine belongs to the human
    /// who shared it, so "my laptop's boards" is expressible and revoking the
    /// user cascades); `None` for a node enrolled with an auth key, which has
    /// no owning human by construction.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn node_owner(&self, node: &NodeId) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT owner_user_id FROM node WHERE id = ?1")
                .bind(node.0.as_str())
                .fetch_optional(self.pool())
                .await?;
        Ok(row.and_then(|r| r.0))
    }

    /// A node's org **and** adoption policy in one query.
    ///
    /// One round trip because this is the inventory hot path: every report a
    /// node sends needs both, and splitting them would double the database
    /// traffic of a fleet's steady state.
    ///
    /// A row whose `adopt_policy` is not a value [`AdoptPolicy::from_label`]
    /// recognises is an **error**, not a default: silently treating an
    /// unparseable policy as `auto` would adopt probes nobody asked to share.
    /// The column's `CHECK` constraint makes one unreachable short of a
    /// hand edit.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails, or
    /// [`CoordinatorError::State`] if
    /// the stored policy is unrecognised.
    pub async fn node_org_and_policy(&self, node: &NodeId) -> Result<Option<(OrgId, AdoptPolicy)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT ns_node_id, adopt_policy FROM node WHERE id = ?1")
                .bind(node.0.as_str())
                .fetch_optional(self.pool())
                .await?;
        match row {
            None => Ok(None),
            Some((org, policy)) => {
                let parsed = AdoptPolicy::from_label(&policy).ok_or_else(|| {
                    crate::error::CoordinatorError::State(format!(
                        "node {} has an unrecognised adopt_policy {policy:?}",
                        node.0
                    ))
                })?;
                Ok(Some((OrgId(org), parsed)))
            }
        }
    }
}

/// The outcome of [`Db::move_node`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMove {
    /// Moved; the node's new id.
    Moved(NodeId),
    /// The source org has no node by that name.
    NotFound,
    /// The target org already has a node by that name.
    NameTaken,
}

/// Turn a forgs grant row into fleet's evaluable [`GrantScope`], or `None` if
/// any stored field no longer parses.
///
/// **Fails closed on purpose.** A selector that will not parse could only be
/// turned into "matches nothing" or "matches everything", and the second is
/// catastrophic; a grant with no recognisable op confers nothing anyway.
#[must_use]
pub fn grant_scope(row: &forgs_store::GrantRow) -> Option<GrantScope> {
    let selector = probefleet_proto::lease::parse_constraint(&row.selector).ok()?;
    let ops = parsed_ops(&row.ops);
    if ops.is_empty() {
        return None;
    }
    Some(GrantScope {
        id: row.id.to_string(),
        org: crate::subject::org_of(row.ns),
        selector,
        ops,
        expires: row.expires,
    })
}

/// Newline-joined op labels, dropping any this build does not recognise.
#[must_use]
pub fn parsed_ops(joined: &str) -> Vec<AllowedOp> {
    joined
        .split('\n')
        .filter(|s| !s.is_empty())
        .filter_map(AllowedOp::from_label)
        .collect()
}

/// Op labels as stored in `forgs_grant.ops` (newline-joined).
#[must_use]
pub fn join_ops(ops: &[AllowedOp]) -> String {
    ops.iter()
        .map(|o| o.as_str())
        .collect::<Vec<_>>()
        .join("\n")
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
    ///
    /// The insert names `adopt_policy` explicitly rather than letting the
    /// column default apply: `0001_init.sql`'s default is the retired
    /// placeholder `'manual'`, which [`AdoptPolicy::from_label`] rejects, so a
    /// defaulted row would fail the policy lookup on the very next report.
    /// `declared` is the conservative choice for a node we hold no explicit
    /// registration for.
    ///
    /// **`ON CONFLICT` deliberately touches only `last_seen`.** This runs on
    /// every inventory report; updating `adopt_policy` here would silently
    /// reset a `share`-created node to `declared` the first time it connected.
    /// The same goes for `name`: an existing row's name is not this path's
    /// business, so it stays in the `VALUES` list only.
    ///
    /// The row is created with the **node-local** name ([`node_name_for`]),
    /// the same spelling [`Db::register_node_full`] writes, so the two
    /// creation paths are indistinguishable in the column the browser API
    /// addresses nodes by ([`OrgDb::node_by_name`]).
    ///
    /// One consequence: the insert can now fail `UNIQUE (ns_node_id, name)`, which
    /// binding the prefixed id never could. It is unreachable in practice —
    /// `register_node_full` derives `id = node_id_for(org, name)`, so any
    /// same-org row with that name has that exact primary key and
    /// `ON CONFLICT(id)` fires first — with one residue: a legacy prefixed row
    /// that `0010_node_name_normalise.sql`'s collision guard skipped. The
    /// caller already handles it (`core.rs` warns and reconciles nothing,
    /// notably pruning no boards).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn ensure_node(&self, node: &NodeId, now: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO node (id, ns_node_id, name, adopt_policy, last_seen, created_at)
             VALUES (?1, ?2, ?3, 'declared', ?4, ?4)
             ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
        )
        .bind(node.0.as_str())
        .bind(self.org.0.as_str())
        .bind(node_name_for(&self.org, node))
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
    /// `presence` is the presence the node reported. Every **admitted** board
    /// is recorded, offline ones included: the table is the set of boards the
    /// node declares (see the module docs), so a board that is declared but has
    /// never been plugged in must still have a row — otherwise
    /// [`OrgDb::prune_boards`]'s keep/delete rule would be incoherent and the
    /// board would silently never appear on the Nodes page. Which boards count
    /// as admitted is decided by the caller
    /// ([`crate::core::Coordinator::reconcile_inventory`]); an adopted board
    /// reported offline is a tombstone and must not be recorded.
    ///
    /// # The `state` column mixes two axes, deliberately
    ///
    /// An offline board is written as `"offline"`, where every other value
    /// (`idle`/`leased`/`faulted`/`disabled`) comes from `board_state_label`,
    /// i.e. from [`BoardState`]. That conflates presence with lease state and
    /// is safe only because the column is **write-only**: nothing in this
    /// module — or anywhere else — selects it back. Treat it as a debugging
    /// label; a future reader must not parse it as a [`BoardState`] without
    /// first splitting the two axes into separate columns.
    ///
    /// `first_seen` / `last_seen` shifted with it, for the same reason:
    /// recording offline boards makes them "first/last **reported**", not
    /// "first/last seen online". A board declared but never plugged in now gets
    /// a row with both set, and an unplugged board's `last_seen` keeps
    /// advancing every `discovery_secs`. Nothing reads either column back today
    /// either (only a test does), but a future "idle since" display must not
    /// assume they mean presence.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails, or
    /// [`crate::error::CoordinatorError::Protocol`] on an org mismatch.
    pub async fn record_board(
        &self,
        board: &Board,
        presence: BoardPresence,
        now: i64,
    ) -> Result<()> {
        if board.id.org != self.org {
            return Err(crate::error::CoordinatorError::Protocol(format!(
                "board {} does not belong to org {}",
                board.id, self.org
            )));
        }
        // Tags are simple identifiers (no newlines); store newline-joined.
        let tags = board.tags.join("\n");
        let state = match presence {
            BoardPresence::Offline => "offline",
            BoardPresence::Online => board_state_label(&board.state),
        };
        sqlx::query(
            "INSERT INTO board (ns_node_id, node_id, name, chip, model, tags, exclusive, state, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(ns_node_id, node_id, name) DO UPDATE SET
                chip = excluded.chip,
                model = excluded.model,
                tags = excluded.tags,
                exclusive = excluded.exclusive,
                state = excluded.state,
                last_seen = excluded.last_seen",
        )
        .bind(self.org.0.as_str())
        .bind(board.id.node.0.as_str())
        .bind(board.id.name.as_str())
        .bind(board.chip.as_str())
        .bind(board.model.as_deref())
        .bind(tags)
        .bind(i64::from(board.exclusive))
        .bind(state)
        .bind(now)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Delete this node's `board` rows for boards it no longer declares.
    ///
    /// `keep` is the set of node-local board names the coordinator admitted
    /// from the node's latest inventory report — *including* the ones it
    /// reported `Offline`, because an offline **declared** board is still
    /// declared (see the module docs). A board absent from `keep` is one the
    /// node stopped declaring: renamed, or removed from `boards.toml`. No
    /// tombstone ever arrives for such a board — the node only reports what is
    /// still in its config — so a set difference is the only thing that can
    /// retire the row.
    ///
    /// An **empty** `keep` deletes every row for this node, deliberately: an
    /// node that reports an empty inventory declares nothing, and the rows
    /// really are gone. The statement degenerates to a plain
    /// `DELETE … WHERE ns_node_id = ? AND node_id = ?` rather than to a
    /// syntactically invalid `NOT IN ()`.
    ///
    /// Scoped by `ns_node_id` **and** `node_id`: another node's boards, and another
    /// tenant's, are not expressible from here.
    ///
    /// Binds `keep.len() + 2` parameters, so a node declaring roughly a
    /// thousand boards would exceed `SQLite`'s default
    /// `SQLITE_MAX_VARIABLE_NUMBER` and fail. The caller treats that as
    /// best-effort and logs it — stale rows, never corruption — and a fleet
    /// with a thousand probes on one machine has other problems first; chunk
    /// the delete if that ever stops being true.
    ///
    /// Returns the number of rows deleted (for the audit detail).
    ///
    /// # Errors
    ///
    /// Returns a database error if the delete fails.
    pub async fn prune_boards(&self, node: &NodeId, keep: &[String]) -> Result<u64> {
        // sqlx has no list binding, so the placeholder list is built here; the
        // names are still bound, never interpolated.
        let mut qb =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new("DELETE FROM board WHERE ns_node_id = ");
        qb.push_bind(self.org.0.as_str());
        qb.push(" AND node_id = ");
        qb.push_bind(node.0.as_str());
        if !keep.is_empty() {
            qb.push(" AND name NOT IN (");
            let mut sep = qb.separated(", ");
            for name in keep {
                sep.push_bind(name.as_str());
            }
            qb.push(")");
        }
        let deleted = qb.build().execute(self.db.pool()).await?.rows_affected();
        Ok(deleted)
    }

    /// Count the boards recorded in this org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn board_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM board WHERE ns_node_id = ?1")
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
            "SELECT 1 FROM board WHERE ns_node_id = ?1 AND node_id = ?2 AND name = ?3",
        )
        .bind(self.org.0.as_str())
        .bind(board.node.0.as_str())
        .bind(board.name.as_str())
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.is_some())
    }

    /// The **reported** tags of one board of this org — `board.tags`, i.e.
    /// what the node's latest inventory declared — or `None` if this org has
    /// no `board` row by that key. UI overrides are not applied here; see
    /// [`OrgDb::board_tag_overrides`].
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn board_reported_tags(
        &self,
        node: &NodeId,
        name: &str,
    ) -> Result<Option<Vec<String>>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT tags FROM board WHERE ns_node_id = ?1 AND node_id = ?2 AND name = ?3",
        )
        .bind(self.org.0.as_str())
        .bind(node.0.as_str())
        .bind(name)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|(t,)| split_tags(&t)))
    }

    /// The reported tags of every board row in this org, keyed by
    /// `(node id, board name)` — for the Devices page's provenance display.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_board_reported_tags(
        &self,
    ) -> Result<std::collections::HashMap<(String, String), Vec<String>>> {
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT node_id, name, tags FROM board WHERE ns_node_id = ?1")
                .bind(self.org.0.as_str())
                .fetch_all(self.db.pool())
                .await?;
        Ok(rows
            .into_iter()
            .map(|(node, name, tags)| ((node, name), split_tags(&tags)))
            .collect())
    }

    /// The UI-set tag overrides of one node's boards, keyed by node-local
    /// board name.
    ///
    /// An override **replaces** the board's reported tags; it is kept in its
    /// own table (`board_tag_override`) so it survives the `board` row being
    /// upserted on every report or pruned when an adopted probe is unplugged.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn board_tag_overrides(
        &self,
        node: &NodeId,
    ) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT name, tags FROM board_tag_override WHERE ns_node_id = ?1 AND node_id = ?2",
        )
        .bind(self.org.0.as_str())
        .bind(node.0.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(name, tags)| (name, split_tags(&tags)))
            .collect())
    }

    /// Every UI-set tag override in this org, keyed by `(node id, board name)`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_board_tag_overrides(
        &self,
    ) -> Result<std::collections::HashMap<(String, String), Vec<String>>> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT node_id, name, tags FROM board_tag_override WHERE ns_node_id = ?1",
        )
        .bind(self.org.0.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(node, name, tags)| ((node, name), split_tags(&tags)))
            .collect())
    }

    /// Set (insert or replace) the UI tag override of one board.
    ///
    /// The caller validates `tags` (`crate::http::valid_tags`) and checks the
    /// board exists; this only writes. `by` is the editor's subject key.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails (including the node
    /// foreign key, for a node this org does not have).
    pub async fn set_board_tags(
        &self,
        node: &NodeId,
        name: &str,
        tags: &[String],
        by: Option<&str>,
        now: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO board_tag_override (ns_node_id, node_id, name, tags, updated_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(ns_node_id, node_id, name) DO UPDATE SET
                tags = excluded.tags,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at",
        )
        .bind(self.org.0.as_str())
        .bind(node.0.as_str())
        .bind(name)
        .bind(tags.join("\n"))
        .bind(by)
        .bind(now)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Remove the UI tag override of one board, reverting it to its reported
    /// tags. Returns `true` if an override existed.
    ///
    /// # Errors
    ///
    /// Returns a database error if the delete fails.
    pub async fn clear_board_tags(&self, node: &NodeId, name: &str) -> Result<bool> {
        let n = sqlx::query(
            "DELETE FROM board_tag_override WHERE ns_node_id = ?1 AND node_id = ?2 AND name = ?3",
        )
        .bind(self.org.0.as_str())
        .bind(node.0.as_str())
        .bind(name)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        Ok(n > 0)
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
            "INSERT INTO leases (lease, ns_node_id, node_id, board_name, holder, granted_at, expires)
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
             WHERE lease = ?1 AND ns_node_id = ?2 AND closed_at IS NULL",
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
             WHERE lease = ?1 AND ns_node_id = ?2 AND closed_at IS NULL",
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
            "SELECT COUNT(*) FROM leases WHERE ns_node_id = ?1 AND closed_at IS NULL",
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
            "INSERT INTO audit_log (ts, ns_node_id, subject, action, node_id, board, lease, detail)
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
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE ns_node_id = ?1")
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
    ) -> Result<Vec<probefleet_proto::admin::LogLine>> {
        let rows: Vec<(i64, String, Option<String>, Option<String>)> = match board {
            Some(b) => {
                sqlx::query_as(
                    "SELECT ts, action, board, detail FROM audit_log
                 WHERE ns_node_id = ?1 AND board = ?2 ORDER BY id DESC LIMIT ?3",
                )
                .bind(self.org.0.as_str())
                .bind(b)
                .bind(limit)
                .fetch_all(self.db.pool())
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT ts, action, board, detail FROM audit_log
                 WHERE ns_node_id = ?1 ORDER BY id DESC LIMIT ?2",
                )
                .bind(self.org.0.as_str())
                .bind(limit)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(
                |(ts, action, board, detail)| probefleet_proto::admin::LogLine {
                    ts,
                    action,
                    board,
                    detail,
                },
            )
            .collect())
    }

    /// Every node in this org, with its board names.
    ///
    /// Two consumers: the browser API (`GET /api/v1/nodes`) and the wire verb
    /// `SidecarToCoord::ListNodes` (`ctl nodes`). Both reach it through
    /// `Coordinator::list_nodes_core`, so the query has one authorization
    /// story and not two.
    ///
    /// It exists because `ctl list` is board-shaped, and a machine that has
    /// plugged in no probes is invisible to it.
    ///
    /// Two rows-per-node deliberately are **not** joined into one query: the
    /// board join would multiply the node columns by the board count and make
    /// `last_seen` arrive once per board. Two statements, assembled here.
    ///
    /// `online` is not a column and is not answered here: liveness lives in the
    /// in-memory [`crate::registry::NodeRegistry`], and a database column that
    /// tried to track it would be wrong every time a process died. The caller
    /// composes the two.
    ///
    /// # Errors
    ///
    /// Returns a database error if either query fails, or
    /// [`CoordinatorError::State`] if a
    /// stored `adopt_policy` is unrecognised — the same loud failure
    /// [`Db::node_org_and_policy`] takes, and for the same reason.
    pub async fn list_nodes(&self) -> Result<Vec<NodeRow>> {
        let rows: Vec<NodeDbRow> = sqlx::query_as(
            "SELECT id, name, tags, owner_user_id, adopt_policy, last_seen, created_at
             FROM node WHERE ns_node_id = ?1 ORDER BY name",
        )
        .bind(self.org.0.as_str())
        .fetch_all(self.db.pool())
        .await?;

        let boards: Vec<(String, String)> =
            sqlx::query_as("SELECT node_id, name FROM board WHERE ns_node_id = ?1 ORDER BY name")
                .bind(self.org.0.as_str())
                .fetch_all(self.db.pool())
                .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (id, name, tags, owner, adopt, last_seen, created_at) in rows {
            let adopt = AdoptPolicy::from_label(&adopt).ok_or_else(|| {
                crate::error::CoordinatorError::State(format!(
                    "node {id} has unknown adopt_policy `{adopt}`"
                ))
            })?;
            let node_boards = boards
                .iter()
                .filter(|(node_id, _)| node_id == &id)
                .map(|(_, board)| board.clone())
                .collect();
            out.push(NodeRow {
                id: NodeId(id),
                name,
                tags: split_tags(&tags),
                owner_user_id: owner.and_then(|o| UserId::parse(&o).ok()),
                adopt,
                last_seen,
                created_at,
                boards: node_boards,
            });
        }
        Ok(out)
    }

    /// One node of this org by its node-local name.
    ///
    /// The browser API addresses nodes by `name` (`UNIQUE (ns_node_id, name)`)
    /// because the id contains a slash and cannot go in a URL path
    /// (`docs/web-ui.md` §3). Scoped through [`OrgDb`], so a name that exists
    /// only in another tenant resolves to `None` — which is what makes
    /// "another org's node" and "no such node" the same answer at the handler.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails, or
    /// [`CoordinatorError::State`] if
    /// the stored `adopt_policy` is unrecognised, exactly as
    /// [`OrgDb::list_nodes`] does.
    pub async fn node_by_name(&self, name: &str) -> Result<Option<NodeRow>> {
        let row: Option<NodeDbRow> = sqlx::query_as(
            "SELECT id, name, tags, owner_user_id, adopt_policy, last_seen, created_at
             FROM node WHERE ns_node_id = ?1 AND name = ?2",
        )
        .bind(self.org.0.as_str())
        .bind(name)
        .fetch_optional(self.db.pool())
        .await?;
        let Some((id, name, tags, owner, adopt, last_seen, created_at)) = row else {
            return Ok(None);
        };
        let adopt = AdoptPolicy::from_label(&adopt).ok_or_else(|| {
            crate::error::CoordinatorError::State(format!(
                "node {id} has unknown adopt_policy `{adopt}`"
            ))
        })?;
        let boards: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM board WHERE ns_node_id = ?1 AND node_id = ?2 ORDER BY name",
        )
        .bind(self.org.0.as_str())
        .bind(id.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(Some(NodeRow {
            id: NodeId(id),
            name,
            tags: split_tags(&tags),
            owner_user_id: owner.and_then(|o| UserId::parse(&o).ok()),
            adopt,
            last_seen,
            created_at,
            boards: boards.into_iter().map(|(b,)| b).collect(),
        }))
    }

    /// Update a node's tags and/or adoption policy, returning the fresh row.
    ///
    /// **`name` is deliberately not updatable.** The node id is `{org}/{name}`
    /// and is the primary key `board.node_id` references under
    /// `PRAGMA foreign_keys = ON`, so a rename would have to cascade through
    /// `board`, the `leases.node_id` column (which has no foreign key and
    /// therefore would *not* be caught) and every live `BoardRef` in the
    /// in-memory scheduler. Refusing is the v1 answer (`docs/web-ui.md` §3);
    /// there is no partial version of it here to be found and "finished" by
    /// somebody who missed the scheduler half.
    ///
    /// `None` for a field leaves it alone — the browser sends a partial
    /// document, and an absent key must not mean "clear it". `Some(vec![])`
    /// *does* clear the tags, which is why tags are an `Option<&[String]>` and
    /// not a bare slice.
    ///
    /// Returns `None` if this org has no node by that name, so the caller
    /// cannot distinguish it from another tenant's.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write or the re-read fails.
    pub async fn update_node(
        &self,
        name: &str,
        tags: Option<&[String]>,
        adopt: Option<AdoptPolicy>,
    ) -> Result<Option<NodeRow>> {
        // Both columns in one statement, each guarded by a NULL sentinel, so a
        // partial update is one round trip and cannot half-apply.
        sqlx::query(
            "UPDATE node
                SET tags = COALESCE(?3, tags),
                    adopt_policy = COALESCE(?4, adopt_policy)
              WHERE ns_node_id = ?1 AND name = ?2",
        )
        .bind(self.org.0.as_str())
        .bind(name)
        .bind(tags.map(|t| t.join("\n")))
        .bind(adopt.map(AdoptPolicy::as_str))
        .execute(self.db.pool())
        .await?;
        self.node_by_name(name).await
    }

    /// Delete a node of this org and the `board` rows that reference it.
    ///
    /// Returns `true` if a row was deleted.
    ///
    /// # Why this exists next to [`Db::delete_node`]
    ///
    /// [`Db::delete_node`] is a bare `DELETE FROM node WHERE id = ?`, and
    /// `board.node_id REFERENCES node(id)` is **enforced** (`0001_init.sql`
    /// sets `PRAGMA foreign_keys = ON`), so it fails outright for any node that
    /// has ever reported a board — i.e. every node worth deleting. The board
    /// rows go first, in one transaction, so a failure leaves the node either
    /// wholly present or wholly gone rather than boardless-but-alive.
    ///
    /// This is only the *persistent* half of a deletion. Deleting the row
    /// revokes the node's token (§4.2), so the caller
    /// ([`crate::core::Coordinator::delete_node_core`]) must also tear down the
    /// node's live leases, drop it from the registry and remove its boards from
    /// the scheduler — none of which this layer can see.
    ///
    /// # Errors
    ///
    /// Returns a database error if any statement fails.
    pub async fn delete_node(&self, name: &str) -> Result<bool> {
        let mut tx = self.db.pool().begin().await?;
        let Some((id,)): Option<(String,)> =
            sqlx::query_as("SELECT id FROM node WHERE ns_node_id = ?1 AND name = ?2")
                .bind(self.org.0.as_str())
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(false);
        };
        sqlx::query("DELETE FROM board WHERE ns_node_id = ?1 AND node_id = ?2")
            .bind(self.org.0.as_str())
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?;
        // Explicit rather than relying on the `ON DELETE CASCADE` alone.
        sqlx::query("DELETE FROM board_tag_override WHERE ns_node_id = ?1 AND node_id = ?2")
            .bind(self.org.0.as_str())
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM node WHERE ns_node_id = ?1 AND id = ?2")
            .bind(self.org.0.as_str())
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted > 0)
    }
}

/// One member of an org, as [`Db::list_members`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// The member's immutable user id.
    pub user_id: UserId,
    /// The username (display; a handle, not an identity).
    pub username: Option<String>,
    /// The role held in this org.
    pub role: FleetRole,
}

/// One row of [`OrgDb::list_nodes`].
///
/// Deliberately **not** the wire type: that is
/// [`probefleet_proto::admin::NodeSummary`], carried by `CoordToSidecar::NodeList`
/// for `ctl nodes`. This stays the *database* shape — it is free to carry
/// columns the wire projection does not — and `core.rs`'s `node_summary` maps
/// one to the other, alongside `api.rs`'s `NodeView` for the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRow {
    /// The node's fleet id (`{org}/{name}`).
    pub id: NodeId,
    /// The node-local name, `UNIQUE (ns_node_id, name)`.
    pub name: String,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// The owning user, if the node was enrolled by a logged-in human. `None`
    /// for an auth-key enrollment, which has no owning human by construction.
    pub owner_user_id: Option<UserId>,
    /// Whether undeclared probes on this node are adopted.
    pub adopt: AdoptPolicy,
    /// Epoch seconds of the last inventory report, if the node has ever
    /// connected.
    pub last_seen: Option<i64>,
    /// Epoch seconds the row was created.
    pub created_at: i64,
    /// The node-local names of the boards recorded for this node.
    pub boards: Vec<String>,
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

/// Derive a node's id from `(org, name)`.
///
/// Deterministic on purpose: re-running `share` / `node up` on the same
/// machine re-enrolls that node (replacing its token) instead of littering the
/// org with duplicate rows for one physical Pi. The id is namespaced by org so
/// the same node name in two tenants is two nodes.
///
/// `pub` rather than private so no caller has to re-implement the format
/// string. A fixture that hand-rolls a domain identifier is a second,
/// unversioned definition of it, and it drifts: `core.rs`'s board fixture
/// built bare ids (`"node-a"`) for long enough that every qualified-name
/// resolution test passed while addressing boards production cannot produce.
/// The in-crate unit tests and the out-of-crate integration fixtures
/// (`tests/common/mod.rs::seed_board`) both call this, so there is exactly one
/// definition of the shape.
#[must_use]
pub fn node_id_for(org: &OrgId, name: &str) -> NodeId {
    NodeId(format!("{}/{name}", org.0))
}

/// The node-local name inside an org-namespaced node id: the inverse of
/// [`node_id_for`].
///
/// Falls back to the whole id when the prefix is absent, rather than panicking
/// or storing an empty name. Every production caller reaches
/// [`OrgDb::ensure_node`] with an id minted by `node_id_for` for *this* org (it
/// comes from the authenticated node subject), so the fallback is unreachable
/// in practice — but a `NOT NULL` column that the browser API keys off is the
/// wrong place to discover that assumption was wrong.
fn node_name_for<'a>(org: &OrgId, node: &'a NodeId) -> &'a str {
    node.0
        .strip_prefix(&format!("{}/", org.0))
        .unwrap_or(node.0.as_str())
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
    use crate::subject::testkit;
    use probefleet_proto::board::PowerKind;

    fn board_in(org: &OrgId, node: &str, name: &str) -> Board {
        Board {
            id: BoardRef::new(org.clone(), node_id_for(org, node), name),
            node: node_id_for(org, node),
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
            tags: vec!["nrf52".to_owned(), "ble".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
            serial_ports: Vec::new(),
        }
    }

    /// An org with one node, so board/lease foreign keys resolve.
    async fn seeded(db: &Db, org_name: &str, node: &str) -> OrgId {
        let o = testkit::org(db, org_name).await;
        db.scoped(o.clone())
            .ensure_node(&node_id_for(&o, node), 1000)
            .await
            .unwrap();
        o
    }

    #[tokio::test]
    async fn ensure_org_named_is_idempotent_and_resolvable() {
        let db = testkit::db().await;
        let a = db.ensure_org_named("acme", 1).await.unwrap();
        assert_eq!(db.ensure_org_named("acme", 2).await.unwrap(), a);
        assert_eq!(db.org_name(&a).await.unwrap().as_deref(), Some("acme"));
        // By path and by id; unknown / malformed is `None`, not an error.
        assert_eq!(db.resolve_org("acme").await.unwrap(), Some(a.clone()));
        assert_eq!(db.resolve_org("/acme/").await.unwrap(), Some(a.clone()));
        assert_eq!(db.resolve_org(&a.0).await.unwrap(), Some(a));
        assert_eq!(db.resolve_org("nope").await.unwrap(), None);
        assert_eq!(db.resolve_org("").await.unwrap(), None);
        assert_eq!(db.resolve_org("a b/c").await.unwrap(), None);
    }

    #[tokio::test]
    async fn reserved_org_names_are_refused() {
        let db = testkit::db().await;
        for name in ["gha", "api", "node", "auth"] {
            assert!(db.ensure_org_named(name, 1).await.is_err(), "{name}");
        }
    }

    #[tokio::test]
    async fn membership_roles_and_personal_org() {
        let db = testkit::db().await;
        let o = testkit::org(&db, "acme").await;
        let alice = testkit::user(&db, "alice").await;
        assert_eq!(db.role_of(&o, alice).await.unwrap(), None);
        db.set_member(&o, alice, FleetRole::Admin, 1).await.unwrap();
        assert_eq!(db.role_of(&o, alice).await.unwrap(), Some(FleetRole::Admin));
        db.set_member(&o, alice, FleetRole::Member, 2)
            .await
            .unwrap();
        assert_eq!(
            db.role_of(&o, alice).await.unwrap(),
            Some(FleetRole::Member)
        );

        let personal = db.personal_org(alice).await.unwrap().expect("personal org");
        assert_eq!(
            db.org_name(&personal).await.unwrap().as_deref(),
            Some("alice")
        );
        let orgs = db.orgs_of_user(alice).await.unwrap();
        assert!(orgs.contains(&(o.clone(), FleetRole::Member)), "{orgs:?}");
        assert!(orgs.iter().any(|(org, _)| *org == personal), "{orgs:?}");

        let members = db.list_members(&o).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user_id, alice);
        assert_eq!(members[0].username.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let db = testkit::db().await;
        let o = testkit::org(&db, "acme").await;
        // No node row: the board is refused.
        let err = db
            .scoped(o.clone())
            .record_board(&board_in(&o, "ghost", "b1"), BoardPresence::Online, 1000)
            .await;
        assert!(err.is_err(), "FK must reject a board with no node row");
        // No org row: the node is refused.
        let ghost = crate::subject::org_of(NsNodeId::from_parts(9, 9));
        let err = db
            .scoped(ghost.clone())
            .ensure_node(&node_id_for(&ghost, "n"), 1000)
            .await;
        assert!(err.is_err(), "FK must reject a node in no org");
    }

    #[tokio::test]
    async fn ensure_node_then_record_board_upserts() {
        let db = testkit::db().await;
        let o = seeded(&db, "acme", "rpi-1").await;
        let scoped = db.scoped(o.clone());
        let b = board_in(&o, "rpi-1", "b1");
        scoped
            .record_board(&b, BoardPresence::Online, 1000)
            .await
            .unwrap();
        scoped
            .record_board(&b, BoardPresence::Online, 2000)
            .await
            .unwrap();
        assert_eq!(scoped.board_count().await.unwrap(), 1);
        assert!(scoped.has_board(&b.id).await.unwrap());
    }

    #[tokio::test]
    async fn record_board_refuses_a_foreign_org_board() {
        let db = testkit::db().await;
        let a = seeded(&db, "org-a", "rpi-1").await;
        let b = seeded(&db, "org-b", "rpi-2").await;
        let err = db
            .scoped(a)
            .record_board(&board_in(&b, "rpi-2", "b1"), BoardPresence::Online, 1000)
            .await;
        assert!(err.is_err(), "cross-org board write must be refused");
    }

    /// A set difference over exactly one node of one org; an empty keep-set
    /// clears that node only.
    #[tokio::test]
    async fn prune_boards_is_scoped_to_one_node_and_one_org() {
        let db = testkit::db().await;
        let mine = seeded(&db, "mine", "rpi-1").await;
        db.scoped(mine.clone())
            .ensure_node(&node_id_for(&mine, "rpi-2"), 1000)
            .await
            .unwrap();
        let theirs = seeded(&db, "theirs", "rpi-9").await;
        for (o, node, name) in [
            (&mine, "rpi-1", "b1"),
            (&mine, "rpi-1", "b2"),
            (&mine, "rpi-2", "b1"),
            (&theirs, "rpi-9", "b1"),
        ] {
            db.scoped(o.clone())
                .record_board(&board_in(o, node, name), BoardPresence::Online, 1000)
                .await
                .unwrap();
        }
        let s = db.scoped(mine.clone());
        let n1 = node_id_for(&mine, "rpi-1");
        assert_eq!(s.prune_boards(&n1, &["b2".to_owned()]).await.unwrap(), 1);
        assert!(!s
            .has_board(&board_in(&mine, "rpi-1", "b1").id)
            .await
            .unwrap());
        assert!(s
            .has_board(&board_in(&mine, "rpi-1", "b2").id)
            .await
            .unwrap());
        assert!(s
            .has_board(&board_in(&mine, "rpi-2", "b1").id)
            .await
            .unwrap());
        assert_eq!(s.prune_boards(&n1, &[]).await.unwrap(), 1);
        assert_eq!(s.board_count().await.unwrap(), 1, "rpi-2's row survives");
        assert_eq!(db.scoped(theirs).board_count().await.unwrap(), 1);
    }

    /// Two orgs' rows never leak into each other's queries.
    #[tokio::test]
    async fn org_scoping_isolates_boards_leases_and_audit() {
        let db = testkit::db().await;
        let a = seeded(&db, "org-a", "node-a").await;
        let b = seeded(&db, "org-b", "node-b").await;
        let (da, db_) = (db.scoped(a.clone()), db.scoped(b.clone()));
        let ba = board_in(&a, "node-a", "dk");
        let bb = board_in(&b, "node-b", "dk");
        da.record_board(&ba, BoardPresence::Online, 1000)
            .await
            .unwrap();
        db_.record_board(&bb, BoardPresence::Online, 1000)
            .await
            .unwrap();
        let alice = testkit::user(&db, "alice").await;
        let holder = crate::subject::user_key(alice);
        da.record_lease(LeaseId(1), &ba.id, &holder, 1000, 2000)
            .await
            .unwrap();
        db_.record_lease(LeaseId(2), &bb.id, &holder, 1000, 2000)
            .await
            .unwrap();
        let subject = holder.to_string();
        da.append_audit(&AuditEntry {
            ts: 1000,
            subject: Some(&subject),
            action: "lease.grant",
            node: Some("node-a"),
            board: Some("dk"),
            lease: Some(LeaseId(1)),
            detail: None,
        })
        .await
        .unwrap();

        assert_eq!(da.board_count().await.unwrap(), 1);
        assert_eq!(db_.board_count().await.unwrap(), 1);
        assert!(!db_.has_board(&ba.id).await.unwrap());

        assert_eq!(da.open_lease_count().await.unwrap(), 1);
        db_.close_lease(LeaseId(1), 1500, "released").await.unwrap();
        db_.update_lease_expiry(LeaseId(1), 9999).await.unwrap();
        assert_eq!(
            da.open_lease_count().await.unwrap(),
            1,
            "B cannot close A's lease"
        );
        let (expires,): (i64,) = sqlx::query_as("SELECT expires FROM leases WHERE lease = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(expires, 2000, "B cannot extend A's lease");
        da.close_lease(LeaseId(1), 1500, "released").await.unwrap();
        assert_eq!(da.open_lease_count().await.unwrap(), 0);

        assert_eq!(da.audit_count().await.unwrap(), 1);
        assert_eq!(db_.audit_count().await.unwrap(), 0);
        assert!(db_.recent_audit(None, 100).await.unwrap().is_empty());
        assert_eq!(da.recent_audit(Some("dk"), 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn node_token_registration_lookup_and_rotation() {
        let db = testkit::db().await;
        let o = testkit::org(&db, "acme").await;
        let tags = vec!["desk".to_owned()];
        let id = db
            .register_node(&o, "rpi-1", "hash-1", &tags, 1000)
            .await
            .unwrap();
        assert_eq!(id, node_id_for(&o, "rpi-1"));
        assert_eq!(
            db.node_by_token_hash("hash-1").await.unwrap(),
            Some((id.clone(), o.clone(), 1000))
        );
        db.set_node_token_hash(&id, "hash-2", 2000).await.unwrap();
        assert_eq!(db.node_by_token_hash("hash-1").await.unwrap(), None);
        assert_eq!(
            db.node_by_token_hash("hash-2").await.unwrap(),
            Some((id.clone(), o.clone(), 2000))
        );
        assert_eq!(db.org_of_node(&id).await.unwrap(), Some(o.clone()));
        assert_eq!(
            db.node_id_in_org_by_name(&o, "rpi-1").await.unwrap(),
            Some(id.0.clone())
        );
        // Org-scoped: the same name elsewhere is not this node.
        let other = testkit::org(&db, "other").await;
        assert_eq!(
            db.node_id_in_org_by_name(&other, "rpi-1").await.unwrap(),
            None
        );
        // Key-enrolled: no owner, conservative policy.
        assert_eq!(db.node_owner(&id).await.unwrap(), None);
        assert_eq!(
            db.node_org_and_policy(&id).await.unwrap(),
            Some((o, AdoptPolicy::Declared))
        );
    }

    /// `ensure_node` (inventory path) never overwrites what a registration
    /// set; re-registering converges on the latest owner and policy.
    #[tokio::test]
    async fn ensure_node_does_not_overwrite_a_registered_policy() {
        let db = testkit::db().await;
        let o = testkit::org(&db, "acme").await;
        let alice = testkit::user(&db, "alice").await;
        let bob = testkit::user(&db, "bob").await;
        let id = db
            .register_node_full(&o, "rpi-1", "h", &[], Some(alice), AdoptPolicy::Auto, 1000)
            .await
            .unwrap();
        db.scoped(o.clone()).ensure_node(&id, 2000).await.unwrap();
        assert_eq!(
            db.node_org_and_policy(&id).await.unwrap(),
            Some((o.clone(), AdoptPolicy::Auto))
        );
        assert_eq!(db.node_owner(&id).await.unwrap(), Some(alice.to_string()));
        db.register_node_full(
            &o,
            "rpi-1",
            "h2",
            &[],
            Some(bob),
            AdoptPolicy::Declared,
            3000,
        )
        .await
        .unwrap();
        assert_eq!(db.node_owner(&id).await.unwrap(), Some(bob.to_string()));
        assert_eq!(
            db.node_org_and_policy(&id).await.unwrap(),
            Some((o.clone(), AdoptPolicy::Declared))
        );

        // A node that only ever reported inventory is `declared`.
        let n2 = node_id_for(&o, "rpi-2");
        db.scoped(o.clone()).ensure_node(&n2, 1000).await.unwrap();
        assert_eq!(
            db.node_org_and_policy(&n2).await.unwrap(),
            Some((o, AdoptPolicy::Declared))
        );
    }

    /// Listing is org-scoped and carries boards; update is partial; delete
    /// cascades.
    #[tokio::test]
    async fn listing_updating_and_deleting_nodes() {
        let db = testkit::db().await;
        let o = seeded(&db, "acme", "a-node").await;
        let other = seeded(&db, "other", "z-node").await;
        let tags = vec!["nrf52".to_owned(), "desk".to_owned()];
        db.register_node(&o, "b-node", "h", &tags, 1000)
            .await
            .unwrap();
        let s = db.scoped(o.clone());
        s.record_board(&board_in(&o, "b-node", "dk"), BoardPresence::Online, 1000)
            .await
            .unwrap();

        let nodes = s.list_nodes().await.unwrap();
        let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["a-node", "b-node"], "org-scoped, sorted");
        assert_eq!(nodes[1].tags, tags);
        assert_eq!(nodes[1].boards, ["dk"]);
        assert!(nodes[0].boards.is_empty());
        assert!(s.node_by_name("z-node").await.unwrap().is_none());
        assert!(db
            .scoped(other)
            .node_by_name("z-node")
            .await
            .unwrap()
            .is_some());

        // Partial update: tags only, policy untouched.
        let row = s
            .update_node("b-node", Some(&["x".to_owned()]), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.tags, ["x"]);
        assert_eq!(row.adopt, AdoptPolicy::Declared);
        let row = s
            .update_node("b-node", None, Some(AdoptPolicy::Auto))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (row.tags.as_slice(), row.adopt),
            (&["x".to_owned()][..], AdoptPolicy::Auto)
        );
        assert!(s.update_node("ghost", None, None).await.unwrap().is_none());

        // Delete cascades to the node's boards and revokes its token.
        assert!(s.delete_node("b-node").await.unwrap());
        assert!(!s.delete_node("b-node").await.unwrap());
        assert_eq!(s.board_count().await.unwrap(), 0);
        assert_eq!(db.node_by_token_hash("h").await.unwrap(), None);
    }

    /// A move re-keys the node and its boards in one transaction, keeps the
    /// token, leaves the foreign keys consistent, and refuses a taken name.
    #[tokio::test]
    async fn move_node_rekeys_node_and_boards() {
        let db = testkit::db().await;
        let a = seeded(&db, "acme", "other-a").await;
        let b = seeded(&db, "beta", "taken").await;
        db.register_node(&a, "rpi", "h", &[], 1000).await.unwrap();
        db.register_node(&a, "taken", "h2", &[], 1000)
            .await
            .unwrap();
        for name in ["dk-1", "dk-2"] {
            db.scoped(a.clone())
                .record_board(&board_in(&a, "rpi", name), BoardPresence::Online, 1000)
                .await
                .unwrap();
        }

        assert_eq!(
            db.move_node(&a, "ghost", &b).await.unwrap(),
            NodeMove::NotFound
        );
        assert_eq!(
            db.move_node(&a, "taken", &b).await.unwrap(),
            NodeMove::NameTaken
        );
        // The refused move rolled back.
        assert!(db
            .scoped(a.clone())
            .node_by_name("taken")
            .await
            .unwrap()
            .is_some());

        let new = node_id_for(&b, "rpi");
        assert_eq!(
            db.move_node(&a, "rpi", &b).await.unwrap(),
            NodeMove::Moved(new.clone())
        );
        assert!(db
            .scoped(a.clone())
            .node_by_name("rpi")
            .await
            .unwrap()
            .is_none());
        let moved = db.scoped(b.clone()).list_nodes().await.unwrap();
        let rpi = moved.iter().find(|n| n.name == "rpi").unwrap();
        assert_eq!(rpi.id, new);
        assert_eq!(rpi.boards, ["dk-1", "dk-2"]);
        assert!(db
            .scoped(a.clone())
            .list_nodes()
            .await
            .unwrap()
            .iter()
            .all(|n| n.name != "rpi"));
        // The token survives and now authenticates the moved node.
        let (id, org, _) = db.node_by_token_hash("h").await.unwrap().unwrap();
        assert_eq!((id, org), (new, b));
        let violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(db.pool())
            .await
            .unwrap()
            .len();
        assert_eq!(violations, 0, "foreign keys hold after the move");
    }

    /// Overrides round-trip, are org-fenced, survive `record_board` and
    /// `prune_boards`, and go with the node.
    #[tokio::test]
    async fn board_tag_overrides_round_trip_and_survive_reports() {
        let db = testkit::db().await;
        let o = seeded(&db, "acme", "rpi-1").await;
        let other = seeded(&db, "other", "rpi-1").await;
        let s = db.scoped(o.clone());
        let n = node_id_for(&o, "rpi-1");
        let b = board_in(&o, "rpi-1", "dk");
        s.record_board(&b, BoardPresence::Online, 1000)
            .await
            .unwrap();
        assert_eq!(
            s.board_reported_tags(&n, "dk").await.unwrap(),
            Some(vec!["nrf52".to_owned(), "ble".to_owned()])
        );
        assert!(s.board_tag_overrides(&n).await.unwrap().is_empty());

        let tags = vec!["lab".to_owned(), "desk".to_owned()];
        s.set_board_tags(&n, "dk", &tags, Some("user:x"), 1000)
            .await
            .unwrap();
        assert_eq!(s.board_tag_overrides(&n).await.unwrap()["dk"], tags);
        assert_eq!(
            s.org_board_tag_overrides().await.unwrap()[&(n.0.clone(), "dk".to_owned())],
            tags
        );
        // Org fence: the other org sees nothing, even for the same node id.
        let so = db.scoped(other.clone());
        assert!(so.org_board_tag_overrides().await.unwrap().is_empty());
        assert!(so.board_tag_overrides(&n).await.unwrap().is_empty());
        assert!(!so.clear_board_tags(&n, "dk").await.unwrap());

        // A re-report rewrites the reported tags, never the override.
        s.record_board(&b, BoardPresence::Online, 2000)
            .await
            .unwrap();
        assert_eq!(s.board_tag_overrides(&n).await.unwrap()["dk"], tags);
        // A prune deletes the row but not the override.
        s.prune_boards(&n, &[]).await.unwrap();
        assert_eq!(s.board_reported_tags(&n, "dk").await.unwrap(), None);
        assert_eq!(s.board_tag_overrides(&n).await.unwrap()["dk"], tags);

        // Clear, then set again and delete the node: the override goes too.
        assert!(s.clear_board_tags(&n, "dk").await.unwrap());
        assert!(!s.clear_board_tags(&n, "dk").await.unwrap());
        s.set_board_tags(&n, "dk", &tags, None, 3000).await.unwrap();
        assert!(s.delete_node("rpi-1").await.unwrap());
        assert!(s.org_board_tag_overrides().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_backed_db_round_trip() {
        let dir = std::env::temp_dir().join(format!("fleet-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fleet.db");
        let path_s = path.to_str().unwrap().to_owned();
        let _ = std::fs::remove_file(&path);
        {
            let db = Db::connect(&path_s).await.unwrap();
            db.ensure_org_named("acme", 1).await.unwrap();
        }
        let db = Db::connect(&path_s).await.unwrap();
        assert!(db.resolve_org("acme").await.unwrap().is_some());
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
