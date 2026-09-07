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
//! declared-but-offline boards, and nothing else.** So the Agents page (which
//! counts rows) may legitimately show more boards than Devices (which lists
//! the scheduler); any other divergence is a bug. The write side of this rule
//! lives in [`crate::core::Coordinator::reconcile_inventory`].

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use fleet_core::access::GrantScope;
use fleet_proto::adopt::AdoptPolicy;
use fleet_proto::agent_api::BoardPresence;
use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{AgentId, BoardRef, LeaseId, OrgId, Role, SubjectKey};
use fleet_proto::token::AllowedOp;

use crate::error::Result;

/// Embedded migrations (run on [`Db::connect`]).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// The org every subject is assigned to until GitHub login exists.
pub const DEFAULT_ORG_ID: &str = "default";

/// `auth_key.purpose` for a key that enrolls a node — the historical meaning,
/// and the default every pre-0007 row carries.
pub const AUTH_KEY_PURPOSE_NODE: &str = "node";
/// `auth_key.purpose` for a key that redeems into a **CI workload** credential
/// (architecture §6.7).
///
/// The distinction is what stops migration 0007 from silently turning every
/// existing enrollment key into a board-access credential.
pub const AUTH_KEY_PURPOSE_CI: &str = "ci";

/// The CI-relevant half of an `auth_key` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiAuthKeyMeta {
    /// `node` or `ci`.
    pub purpose: String,
    /// Op labels the synthesised grant confers; empty means the redemption
    /// path's default.
    pub ops: Vec<String>,
    /// The key's expiry, which the synthesised grant inherits.
    pub expires: Option<i64>,
    /// The operator-chosen identity name (`auth-key create --as`), if any.
    ///
    /// `None` means the redemption path derives the subject from the key hash,
    /// exactly as it did before migration 0009 — see that file for why absence
    /// has exactly one spelling.
    pub subject_name: Option<String>,
}

/// One `auth_key` row as `SQLite` hands it back.
///
/// Named rather than written inline so the eight-tuple does not become an
/// unreadable annotation at the query site.
type AuthKeyRow = (
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    Option<String>,
    String,
    Option<String>,
);

/// One `grant` row as `SQLite` hands it back.
type GrantDbRow = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    i64,
);

/// One stored grant, as read back from the database.
///
/// Deliberately **unvalidated**: `subject`, `selector` and `ops` are the raw
/// stored strings, because a row whose selector no longer parses must be
/// visible to `grant list` (and revocable) rather than poisoning the whole
/// query. Turning a row into something that grants access is
/// [`GrantRow::to_scope`], which fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// Opaque grant id (32 hex chars).
    pub id: String,
    /// The org whose hardware is shared.
    pub org: OrgId,
    /// The rendered [`SubjectKey`] the grant was issued to.
    pub subject: String,
    /// The canonical rendered selector.
    pub selector: String,
    /// Newline-joined op labels.
    pub ops: String,
    /// Expiry (epoch seconds), or `None`.
    pub expires: Option<i64>,
    /// The user who created the grant, if recorded.
    pub created_by: Option<String>,
    /// When the grant was created (epoch seconds).
    pub created_at: i64,
}

/// The claim columns recorded alongside a workload token.
///
/// A struct rather than six positional arguments because every field is an
/// `Option<String>` and transposing two of them would be invisible at the call
/// site — and because it is the right place to state, once, that **none of
/// these takes part in an authorization decision**. `repository` is the
/// exception only in that it is *also* the subject id, decided before this
/// struct is built.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadClaimColumns {
    /// `owner/name`, lowercased. OIDC path only.
    pub repository: Option<String>,
    /// The repository's owner. **Recorded, never authorizing** — a fork or a
    /// new repo under a granted owner must not inherit access (§6.7).
    pub repository_owner: Option<String>,
    /// The git ref the job ran on. Recorded; per-ref conditions are a
    /// follow-up, not v1.
    pub git_ref: Option<String>,
    /// The workflow's name.
    pub workflow: Option<String>,
    /// The fully-qualified workflow reference.
    pub job_workflow_ref: Option<String>,
    /// The Actions run id — the handle an operator uses to find the job.
    pub run_id: Option<String>,
}

impl GrantRow {
    fn from_row(row: GrantDbRow) -> Self {
        let (id, org, subject, selector, ops, expires, created_by, created_at) = row;
        Self {
            id,
            org: OrgId(org),
            subject,
            selector,
            ops,
            expires,
            created_by,
            created_at,
        }
    }

    /// The op labels, dropping any this build does not recognise.
    #[must_use]
    pub fn parsed_ops(&self) -> Vec<AllowedOp> {
        self.ops
            .split('\n')
            .filter(|s| !s.is_empty())
            .filter_map(AllowedOp::from_label)
            .collect()
    }

    /// The subject this grant was issued to, if the stored key parses.
    #[must_use]
    pub fn parsed_subject(&self) -> Option<SubjectKey> {
        SubjectKey::parse(&self.subject)
    }

    /// Turn the row into an evaluable [`GrantScope`], or `None` if any stored
    /// field no longer parses.
    ///
    /// **Fails closed on purpose.** A selector that will not parse could only
    /// be turned into "matches nothing" or "matches everything", and the second
    /// is catastrophic; a grant with no recognisable op confers nothing anyway.
    /// The caller is expected to `warn!` so a corrupt row is noticed rather
    /// than quietly ignored.
    #[must_use]
    pub fn to_scope(&self) -> Option<GrantScope> {
        let selector =
            fleet_proto::lease::parse_constraint(&self.selector)
                .ok()?;
        let ops = self.parsed_ops();
        if ops.is_empty() {
            return None;
        }
        Some(GrantScope {
            id: self.id.clone(),
            org: self.org.clone(),
            selector,
            ops,
            expires: self.expires.map(|e| u64::try_from(e).unwrap_or(0)),
        })
    }
}

/// A handle to the coordinator's `SQLite` database. Cheap to clone (wraps a pool).
#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
}

/// One auth key as an operator sees it (`coordinator auth-keys`).
///
/// Deliberately hash-only: the secret was never stored, so a listing is safe to
/// print, pipe and log. The hash prefix is what `coordinator auth-key-revoke`
/// takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKeyListing {
    /// Lowercase-hex SHA-256 of the key. The only handle to it that exists.
    pub key_hash: String,
    /// Selection tags stamped onto nodes enrolled with this key.
    pub tags: Vec<String>,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// Expiry (epoch seconds), or `None` for a key that never expires.
    pub expires: Option<i64>,
    /// When the key was consumed (epoch seconds), if it was.
    pub consumed_at: Option<i64>,
    /// When the key was minted (epoch seconds).
    pub created_at: i64,
    /// The user who minted the key, or `None` when it was minted from a shell
    /// on the coordinator host (`coordinator auth-key`).
    ///
    /// Load-bearing, not decorative: `POST /auth/keys` lets the *creator*
    /// revoke their own key, and an org admin revoke any key including the
    /// shell-minted ones this column leaves `NULL`.
    pub created_by: Option<String>,
    /// What the key is for (`node` | `ci`).
    ///
    /// Listed because revoking a `ci` key also revokes the grant it
    /// synthesised, and therefore tears down live leases (architecture §6.7).
    /// An operator who cannot see which kind a key is will revoke one and be
    /// surprised by what else disappears.
    pub purpose: String,
    /// The identity this key speaks as (`auth-key create --as`), or `None` for
    /// the hash-derived subject.
    ///
    /// Load-bearing in a listing for the same reason `purpose` is, and more
    /// sharply: keys sharing a name share **one grant row**, so revoking any
    /// one of them tears that grant down and releases the leases held under
    /// the identity — including another key's runner. An operator must be able
    /// to see which keys share a name before revoking one (§6.7).
    pub subject_name: Option<String>,
}

/// One `pending_node` row as `SQLite` hands it back.
///
/// Named rather than written inline so the eleven-tuple does not become an
/// unreadable annotation at three query sites.
type PendingNodeRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

/// One `node` row as `SQLite` hands it back to [`OrgDb::list_nodes`].
///
/// Named rather than written inline for the reason [`PendingNodeRow`] is: a
/// seven-tuple is an unreadable annotation, and this one is read twice (once as
/// the query's type, once as the destructuring).
type NodeDbRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    Option<i64>,
    i64,
);

/// A node registration awaiting a human's approval (architecture §4.2 rung 3).
///
/// The one object in the schema with **no org until it is decided** — which org
/// it joins is what the approval chooses — so it lives on [`Db`] rather than
/// [`OrgDb`]. See `migrations/0005_pending_node.sql`.
///
/// `node_name` and `tags` arrive from an unauthenticated request and are
/// therefore attacker-controlled; the route validates them against a
/// conservative charset before they are stored, because they end up rendered in
/// a human approver's terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNode {
    /// The normalised short code (no hyphen).
    pub user_code: String,
    /// The name the enrolling machine asked for.
    pub node_name: String,
    /// The tags it asked for.
    pub tags: Vec<String>,
    /// The adoption policy it asked for.
    pub adopt: AdoptPolicy,
    /// The source address the coordinator saw, if the serve path provided one.
    /// Advisory — behind a proxy this is the proxy.
    pub source_ip: Option<String>,
    /// When the registration was started (epoch seconds).
    pub created_at: i64,
    /// When it expires (epoch seconds).
    pub expires: i64,
    /// The org it was bound to, once approved.
    pub org: Option<OrgId>,
    /// The user who approved it.
    pub approved_by: Option<String>,
    /// When it was approved (epoch seconds).
    pub approved_at: Option<i64>,
    /// When it was redeemed **or denied** (epoch seconds). Denial is
    /// "consumed without having been approved"; there is deliberately no
    /// `denied_at`.
    pub consumed_at: Option<i64>,
}

impl PendingNode {
    /// Whether this registration can still be approved or denied.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.approved_at.is_none() && self.consumed_at.is_none()
    }

    /// Whether it was denied (consumed without ever being approved).
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.approved_at.is_none() && self.consumed_at.is_some()
    }

    /// Whether it is approved and not yet redeemed.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.approved_at.is_some() && self.consumed_at.is_none()
    }

    /// The `pending` | `approved` | `denied` label the wire uses.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        if self.is_denied() {
            "denied"
        } else if self.approved_at.is_some() {
            "approved"
        } else {
            "pending"
        }
    }

    fn from_row(row: PendingNodeRow) -> Self {
        let (
            user_code,
            node_name,
            tags,
            adopt,
            source_ip,
            created_at,
            expires,
            org,
            approved_by,
            approved_at,
            consumed_at,
        ) = row;
        Self {
            user_code,
            node_name,
            tags: split_tags(&tags),
            // As in `consume_pending_node`: an unparseable stored policy means
            // hand-edited state, and `declared` is the conservative landing.
            adopt: AdoptPolicy::from_label(&adopt).unwrap_or(AdoptPolicy::Declared),
            source_ip,
            created_at,
            expires,
            org: org.map(OrgId),
            approved_by,
            approved_at,
            consumed_at,
        }
    }
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
    /// Refuses the reserved CI-workload namespace
    /// ([`fleet_proto::ids::WORKLOAD_NS_GHA`]). That namespace has a real `org`
    /// row — migration 0007 creates it, of kind `system`, so the audit-log
    /// foreign key holds on the rare paths that fall back to an acting
    /// subject's org — but nothing may *reuse* it as a tenant. Reserving it
    /// here rather than only in `CoordinatorConfig::validate` is the point:
    /// admin verbs reach this function with an operator-supplied name, and a
    /// reserved name that only one creation path respects is a trap for the
    /// next change.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails, or
    /// [`crate::error::CoordinatorError::Config`] if `org` is the reserved
    /// namespace.
    pub async fn ensure_org(&self, org: &OrgId, kind: &str) -> Result<()> {
        if org.0 == fleet_proto::ids::WORKLOAD_NS_GHA {
            return Err(crate::error::CoordinatorError::Config(format!(
                "`{}` is a reserved namespace for CI workload subjects and cannot be an org",
                fleet_proto::ids::WORKLOAD_NS_GHA
            )));
        }
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
        let row: Option<(String, String, Option<i64>)> =
            sqlx::query_as("SELECT id, org_id, token_issued_at FROM node WHERE token_hash = ?1")
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
    /// The auth-key path (`POST /auth/token`, `grant_type: "auth_key"`): the
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
    ) -> Result<AgentId> {
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
    /// `agent up` on the same machine re-enrolls it rather than creating a
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
        owner_user_id: Option<&str>,
        adopt: AdoptPolicy,
        now: i64,
    ) -> Result<AgentId> {
        let node_id = node_id_for(org, name);
        sqlx::query(
            "INSERT INTO node (id, org_id, owner_user_id, name, tags, token_hash, token_issued_at, adopt_policy, last_seen, created_at)
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
        .bind(owner_user_id)
        .bind(name)
        .bind(tags.join("\n"))
        .bind(token_hash)
        .bind(now)
        .bind(adopt.as_str())
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
        let row: Option<(String, String, i64)> =
            sqlx::query_as("SELECT user_id, org_id, expires FROM session WHERE token_hash = ?1")
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

    /// Record a freshly minted CI workload token (architecture §6.7).
    ///
    /// # Why this is on [`Db`] and not [`OrgDb`]
    ///
    /// For the same reason [`Db::grants_for_subject`] is, read from the other
    /// side: **a workload belongs to no org.** Its subject is a repo in a
    /// reserved namespace, several orgs may independently grant it access, and
    /// it is a member of none of them — so there is no org to scope by that
    /// would not be an arbitrary pick among the granting orgs. The scoping key
    /// is the token hash, which *is* the credential and which no caller can
    /// enumerate.
    ///
    /// The claim columns (`repository_owner`, `git_ref`, `workflow`,
    /// `job_workflow_ref`, `run_id`) are recorded for audit and metering and
    /// are **never** read by an authorization decision.
    ///
    /// # Errors
    ///
    /// Returns a database error if the insert fails.
    pub async fn insert_workload_token(
        &self,
        token_hash: &str,
        subject: &SubjectKey,
        kind: &str,
        claims: &WorkloadClaimColumns,
        issued_at: i64,
        expires: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workload_token
               (token_hash, subject, kind, repository, repository_owner,
                git_ref, workflow, job_workflow_ref, run_id, issued_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(token_hash)
        .bind(subject.to_string())
        .bind(kind)
        .bind(claims.repository.as_deref())
        .bind(claims.repository_owner.as_deref())
        .bind(claims.git_ref.as_deref())
        .bind(claims.workflow.as_deref())
        .bind(claims.job_workflow_ref.as_deref())
        .bind(claims.run_id.as_deref())
        .bind(issued_at)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up a workload token by hash: `(rendered subject, expires)`.
    ///
    /// Expiry is **not** filtered here, deliberately: `fleet-auth` compares it
    /// against the coordinator's clock so an expired credential is
    /// `AuthError::Expired` rather than the indistinguishable
    /// `AuthError::Unknown` — the difference between an operator diagnosing a
    /// long job and hunting a phantom revocation.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn workload_by_token_hash(&self, token_hash: &str) -> Result<Option<(String, i64)>> {
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT subject, expires FROM workload_token WHERE token_hash = ?1")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    /// Delete every workload token that expired at or before `now`; returns the
    /// count.
    ///
    /// The highest-churn credential in the schema (one row per CI job), which
    /// is why the sweep runs it beside the session sweep and why the table
    /// carries an index on `expires`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_expired_workload_tokens(&self, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM workload_token WHERE expires <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// The CI-relevant metadata of an auth key, by hash.
    ///
    /// Read **before** the atomic consume, so redeeming a `node` key at the CI
    /// grant type does not burn a single-use enrollment key on its way to a
    /// `403`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn ci_auth_key_meta(&self, key_hash: &str) -> Result<Option<CiAuthKeyMeta>> {
        let row: Option<(String, String, Option<i64>, Option<String>)> = sqlx::query_as(
            "SELECT purpose, ops, expires, subject_name FROM auth_key
             WHERE key_hash = ?1 AND consumed_at IS NULL",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(purpose, ops, expires, subject_name)| CiAuthKeyMeta {
            purpose,
            ops: split_tags(&ops),
            expires,
            subject_name,
        }))
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
        self.insert_auth_key_with_purpose(
            org,
            key_hash,
            tags,
            single_use,
            expires,
            created_by,
            created_at,
            AUTH_KEY_PURPOSE_NODE,
            &[],
            None,
        )
        .await
    }

    /// Insert an auth key with an explicit purpose (architecture §6.7).
    ///
    /// [`Db::insert_auth_key`] is the node-enrollment spelling and stays the
    /// default, so a caller has to *ask* for a CI key. That asymmetry is
    /// deliberate: a key that can lease hardware is a different credential from
    /// one that can offer it, and the difference must be visible at the call
    /// site rather than in a boolean at the end of an argument list.
    ///
    /// `subject_name` is the operator-chosen identity a `ci` key speaks as
    /// (`--as <name>`), already normalised by
    /// `fleet_proto::ids::normalise_agent_name`; `None` keeps the historical
    /// hash-derived subject. It is refused for a `node` key at every mint path,
    /// because a node key confers no subject for it to name.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_auth_key_with_purpose(
        &self,
        org: &OrgId,
        key_hash: &str,
        tags: &[String],
        single_use: bool,
        expires: Option<i64>,
        created_by: Option<&str>,
        created_at: i64,
        purpose: &str,
        ops: &[String],
        subject_name: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO auth_key
               (key_hash, org_id, tags, single_use, expires, created_by, created_at, purpose, ops,
                subject_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(key_hash)
        .bind(org.0.as_str())
        .bind(tags.join("\n"))
        .bind(i64::from(single_use))
        .bind(expires)
        .bind(created_by)
        .bind(created_at)
        .bind(purpose)
        .bind(ops.join("\n"))
        .bind(subject_name)
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

    /// Every auth key in `org`, newest first.
    ///
    /// The secret is not stored (only its SHA-256), so what comes back is the
    /// hash — which is exactly what makes a key listable at all: an operator
    /// can see what exists, when it expires, and whether it has been used,
    /// without the listing itself being a credential.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn list_auth_keys(&self, org: &OrgId) -> Result<Vec<AuthKeyListing>> {
        let rows: Vec<AuthKeyRow> = sqlx::query_as(
            "SELECT key_hash, tags, single_use, expires, consumed_at, created_at, created_by,
                    purpose, subject_name
             FROM auth_key WHERE org_id = ?1 ORDER BY created_at DESC",
        )
        .bind(org.0.as_str())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    key_hash,
                    tags,
                    single_use,
                    expires,
                    consumed_at,
                    created_at,
                    created_by,
                    purpose,
                    subject_name,
                )| {
                    AuthKeyListing {
                        key_hash,
                        tags: split_tags(&tags),
                        single_use: single_use != 0,
                        expires,
                        consumed_at,
                        created_at,
                        created_by,
                        purpose,
                        subject_name,
                    }
                },
            )
            .collect())
    }

    /// Revoke auth keys whose hash starts with `prefix`, within `org`.
    ///
    /// Returns the hashes deleted. The caller is expected to refuse an
    /// ambiguous prefix *before* calling; this returns the full set so that
    /// refusal can name what it matched. Revocation is a `DELETE` for the same
    /// reason node revocation is: it is trivially auditable, and there is no
    /// tombstone to forget to check.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn delete_auth_keys_by_prefix(
        &self,
        org: &OrgId,
        prefix: &str,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "DELETE FROM auth_key WHERE org_id = ?1 AND key_hash LIKE ?2 || '%'
             RETURNING key_hash",
        )
        .bind(org.0.as_str())
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
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

    /// Insert a pending node registration, retrying on a `user_code` collision.
    ///
    /// The caller supplies fresh codes through `next_code` rather than a single
    /// value, because `user_code` is the primary key: at ~40 bits behind a
    /// 15-minute TTL a collision is astronomically unlikely, but an
    /// unauthenticated route must not have an unhandled `Err` path for it.
    /// Three attempts, then the error surfaces as a `500`.
    ///
    /// # Errors
    ///
    /// Returns a database error if every attempt fails.
    // One argument per column, and the columns are the pending registration's
    // whole definition (the same reasoning as `insert_auth_key`).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_pending_node(
        &self,
        mut next_code: impl FnMut() -> String,
        device_hash: &str,
        node_name: &str,
        tags: &[String],
        adopt: AdoptPolicy,
        source_ip: Option<&str>,
        created_at: i64,
        expires: i64,
    ) -> Result<String> {
        // The last attempt is outside the loop so its error is returned
        // directly: there is then no "we finished the loop with no error
        // recorded" branch to fabricate, and therefore no panic path on a route
        // an unauthenticated caller can reach.
        for _ in 0..2 {
            let code = next_code();
            if self
                .try_insert_pending_node(
                    &code,
                    device_hash,
                    node_name,
                    tags,
                    adopt,
                    source_ip,
                    created_at,
                    expires,
                )
                .await
                .is_ok()
            {
                return Ok(code);
            }
        }
        let code = next_code();
        self.try_insert_pending_node(
            &code,
            device_hash,
            node_name,
            tags,
            adopt,
            source_ip,
            created_at,
            expires,
        )
        .await?;
        Ok(code)
    }

    /// One insert attempt. Fails on a `user_code` collision, which is what
    /// [`Db::insert_pending_node`] retries past.
    #[allow(clippy::too_many_arguments)]
    async fn try_insert_pending_node(
        &self,
        code: &str,
        device_hash: &str,
        node_name: &str,
        tags: &[String],
        adopt: AdoptPolicy,
        source_ip: Option<&str>,
        created_at: i64,
        expires: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO pending_node
                 (user_code, device_hash, node_name, tags, adopt_policy, source_ip,
                  created_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(code)
        .bind(device_hash)
        .bind(node_name)
        .bind(tags.join("\n"))
        .bind(adopt.as_str())
        .bind(source_ip)
        .bind(created_at)
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How many pending registrations are live (neither consumed nor expired).
    ///
    /// The ceiling `/node/register/start` enforces before its insert. Cheap:
    /// the table is TTL-bounded and swept.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn live_pending_node_count(&self, now: i64) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM pending_node WHERE consumed_at IS NULL AND expires > ?1",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Look up a live pending registration by its normalised code.
    ///
    /// "Live" means unexpired; an already-decided row is returned so the caller
    /// can distinguish approve/deny/redeemed states. Expired and unknown are
    /// both `None`, which is what lets the route answer them uniformly.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn pending_node_by_code(&self, code: &str, now: i64) -> Result<Option<PendingNode>> {
        let row: Option<PendingNodeRow> = sqlx::query_as(
            "SELECT user_code, node_name, tags, adopt_policy, source_ip, created_at, expires,
                    org_id, approved_by, approved_at, consumed_at
             FROM pending_node WHERE user_code = ?1 AND expires > ?2",
        )
        .bind(code)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(PendingNode::from_row))
    }

    /// Approve a pending registration: bind it to `org` and `approver`.
    ///
    /// **One conditional UPDATE**, so two concurrent approvals cannot bind two
    /// orgs: the second one matches no row and is reported as already decided.
    /// Returns `true` when this call is the one that approved it.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn approve_pending_node(
        &self,
        code: &str,
        org: &OrgId,
        approver: &str,
        now: i64,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE pending_node
                SET org_id = ?2, approved_by = ?3, approved_at = ?4
              WHERE user_code = ?1
                AND approved_at IS NULL
                AND consumed_at IS NULL
                AND expires > ?4",
        )
        .bind(code)
        .bind(org.0.as_str())
        .bind(approver)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Deny a pending registration, permanently.
    ///
    /// Same conditional shape as [`Db::approve_pending_node`], setting only
    /// `consumed_at` — a denied row is "consumed without ever being approved"
    /// (see the migration header).
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn deny_pending_node(&self, code: &str, now: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE pending_node
                SET consumed_at = ?2
              WHERE user_code = ?1
                AND approved_at IS NULL
                AND consumed_at IS NULL
                AND expires > ?2",
        )
        .bind(code)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Look up a live pending registration by its device-secret hash.
    ///
    /// Read-only, for the poll route's outcome reporting; redemption itself
    /// goes through [`Db::consume_pending_node`], which is the guard.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn pending_node_by_device_hash(
        &self,
        device_hash: &str,
        now: i64,
    ) -> Result<Option<PendingNode>> {
        let row: Option<PendingNodeRow> = sqlx::query_as(
            "SELECT user_code, node_name, tags, adopt_policy, source_ip, created_at, expires,
                    org_id, approved_by, approved_at, consumed_at
             FROM pending_node WHERE device_hash = ?1 AND expires > ?2",
        )
        .bind(device_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(PendingNode::from_row))
    }

    /// Atomically redeem an approved pending registration.
    ///
    /// **The single atomic consume**, exactly as [`Db::consume_auth_key`] is:
    /// one conditional `UPDATE … RETURNING`, so a node token is minted at most
    /// once however many polls race. Every check the route makes before calling
    /// this is a courtesy that lets it report *why*, not the guard.
    ///
    /// Returns `(org, approver, node_name, tags, adopt)`, or `None` when the
    /// registration is unknown, unapproved, already redeemed, denied or
    /// expired.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn consume_pending_node(
        &self,
        device_hash: &str,
        now: i64,
    ) -> Result<Option<(OrgId, String, String, Vec<String>, AdoptPolicy)>> {
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            "UPDATE pending_node
                SET consumed_at = ?2
              WHERE device_hash = ?1
                AND approved_at IS NOT NULL
                AND consumed_at IS NULL
                AND expires > ?2
            RETURNING org_id, approved_by, node_name, tags, adopt_policy",
        )
        .bind(device_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(org, approver, name, tags, adopt)| {
            (
                OrgId(org),
                approver,
                name,
                split_tags(&tags),
                // A row's policy was validated at insert; an unparseable one
                // means hand-edited state, and `declared` is the conservative
                // landing place (the same choice migration 0004 made).
                AdoptPolicy::from_label(&adopt).unwrap_or(AdoptPolicy::Declared),
            )
        }))
    }

    /// Every live pending registration, newest first: `(user_code, node_name)`.
    ///
    /// Not test scaffolding: this is the query a `node list-pending` verb wants,
    /// and the integration tests use it to learn the code the enrolling machine
    /// printed.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn live_pending_codes(&self, now: i64) -> Result<Vec<(String, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT user_code, node_name FROM pending_node
              WHERE consumed_at IS NULL AND expires > ?1
              ORDER BY created_at DESC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Delete pending registrations that have expired or been consumed.
    ///
    /// Hygiene, **not** the security boundary — expiry and single-use are
    /// enforced at redemption by the conditional statements above. Returns the
    /// number of rows removed.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn delete_expired_pending_nodes(&self, now: i64) -> Result<u64> {
        let result =
            sqlx::query("DELETE FROM pending_node WHERE expires <= ?1 OR consumed_at IS NOT NULL")
                .bind(now)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
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
            sqlx::query_as("SELECT id FROM node WHERE org_id = ?1 AND name = ?2")
                .bind(org.0.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(id,)| id))
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
    pub async fn node_owner(&self, node: &AgentId) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT owner_user_id FROM node WHERE id = ?1")
                .bind(node.0.as_str())
                .fetch_optional(&self.pool)
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
    /// Migration `0004_adopt_policy.sql` rewrites the one such value that ever
    /// existed (`'manual'`).
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails, or
    /// [`CoordinatorError::State`](crate::error::CoordinatorError::State) if
    /// the stored policy is unrecognised.
    pub async fn node_org_and_policy(
        &self,
        node: &AgentId,
    ) -> Result<Option<(OrgId, AdoptPolicy)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT org_id, adopt_policy FROM node WHERE id = ?1")
                .bind(node.0.as_str())
                .fetch_optional(&self.pool)
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

    /// The slug **and kind** of an org, for display.
    ///
    /// One query because the browser's `GET /api/v1/org` wants both and they
    /// live in the same row; [`Db::org_slug`] stays for the callers that want
    /// only the slug.
    ///
    /// `kind` is `personal` | `team` | `system` as written by
    /// [`Db::ensure_org`]. It is returned as the stored string rather than
    /// parsed into an enum: nothing branches on it, it is a display label, and
    /// an unrecognised value should surface as itself rather than be collapsed
    /// into a guess — the same discipline `adopt_policy` takes, minus the
    /// loudness, because nothing here is a security decision.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn org_slug_and_kind(&self, org: &OrgId) -> Result<Option<(String, String)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT slug, kind FROM org WHERE id = ?1")
                .bind(org.0.as_str())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
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

    /// The cached GitHub login of a user, for **display only**.
    ///
    /// The inverse of [`Db::user_by_login`], and the asymmetry is deliberate:
    /// that one exists because a grant resolves a typed name to an immutable
    /// id *once*, while this one never feeds a decision. `None` for a user
    /// created by the interim `coordinator user-token` verb, which has no
    /// GitHub identity to cache — and it stays `None` all the way to the JSON
    /// rather than being defaulted to the id, because a UI that showed the id
    /// as a login would be showing something the human never chose.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn user_login(&self, user_id: &str) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT login FROM user WHERE id = ?1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|r| r.0))
    }

    /// Look up a user by their GitHub login, returning `(user id, personal org)`.
    ///
    /// The **only** place the mutable `login` column is used as a lookup key,
    /// and it is safe here for a specific reason: the result is immediately
    /// resolved to the immutable `user.id` and it is *that* which is stored in
    /// the grant. `grant bob` therefore means "the account that is `bob`
    /// right now", decided once, at creation — not "whoever holds the login
    /// `bob` at evaluation time", which §6.4's rename/reuse takeover would make
    /// a hole.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn user_by_login(&self, login: &str) -> Result<Option<(String, OrgId)>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT id, personal_org_id FROM user WHERE login = ?1")
                .bind(login)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(id, org)| (id, OrgId(org))))
    }

    /// Every live grant issued **to** `subject`, across all orgs.
    ///
    /// # Why this is not on [`OrgDb`]
    ///
    /// This is the single query in the tree that deliberately reads outside the
    /// org-scoping type, and it needs to read as a decision rather than an
    /// oversight, so: **a grant's entire purpose is to cross an org boundary.**
    /// Scoping it to the caller's org would return exactly the rows that do not
    /// matter. The scoping key here is the *subject* instead, and that is not
    /// weaker: a `SubjectKey` is derived from the authenticated `Subject` and
    /// there is no wire field a caller can use to name a different one — the
    /// same structural property that makes `OrgDb` safe, applied to a different
    /// column.
    ///
    /// Expired rows are filtered here so a stale grant cannot widen access even
    /// if a caller forgets the `now` check downstream; `Access` checks expiry
    /// again anyway.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn grants_for_subject(
        &self,
        subject: &SubjectKey,
        now: i64,
    ) -> Result<Vec<GrantRow>> {
        let rows: Vec<GrantDbRow> = sqlx::query_as(
            "SELECT id, org_id, subject, selector, ops, expires, created_by, created_at
             FROM \"grant\"
             WHERE subject = ?1 AND (expires IS NULL OR expires > ?2)
             ORDER BY created_at DESC",
        )
        .bind(subject.to_string())
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(GrantRow::from_row).collect())
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
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    pub async fn ensure_node(&self, node: &AgentId, now: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO node (id, org_id, name, adopt_policy, last_seen, created_at)
             VALUES (?1, ?2, ?3, 'declared', ?4, ?4)
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
    /// `presence` is the presence the node reported. Every **admitted** board
    /// is recorded, offline ones included: the table is the set of boards the
    /// node declares (see the module docs), so a board that is declared but has
    /// never been plugged in must still have a row — otherwise
    /// [`OrgDb::prune_boards`]'s keep/delete rule would be incoherent and the
    /// board would silently never appear on the Agents page. Which boards count
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
            "INSERT INTO board (org_id, node_id, name, chip, model, tags, exclusive, state, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(org_id, node_id, name) DO UPDATE SET
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
    /// tombstone ever arrives for such a board — the agent only reports what is
    /// still in its config — so a set difference is the only thing that can
    /// retire the row.
    ///
    /// An **empty** `keep` deletes every row for this node, deliberately: an
    /// agent that reports an empty inventory declares nothing, and the rows
    /// really are gone. The statement degenerates to a plain
    /// `DELETE … WHERE org_id = ? AND node_id = ?` rather than to a
    /// syntactically invalid `NOT IN ()`.
    ///
    /// Scoped by `org_id` **and** `node_id`: another node's boards, and another
    /// tenant's, are not expressible from here.
    ///
    /// Binds `keep.len() + 2` parameters, so a node declaring roughly a
    /// thousand boards would exceed SQLite's default
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
    pub async fn prune_boards(&self, node: &AgentId, keep: &[String]) -> Result<u64> {
        // sqlx has no list binding, so the placeholder list is built here; the
        // names are still bound, never interpolated.
        let mut qb =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new("DELETE FROM board WHERE org_id = ");
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
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM board WHERE org_id = ?1 AND node_id = ?2 AND name = ?3")
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
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM leases WHERE org_id = ?1 AND closed_at IS NULL")
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
            Some(b) => {
                sqlx::query_as(
                    "SELECT ts, action, board, detail FROM audit_log
                 WHERE org_id = ?1 AND board = ?2 ORDER BY id DESC LIMIT ?3",
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
                 WHERE org_id = ?1 ORDER BY id DESC LIMIT ?2",
                )
                .bind(self.org.0.as_str())
                .bind(limit)
                .fetch_all(self.db.pool())
                .await?
            }
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

    // -----------------------------------------------------------------------
    // Grants (architecture §6.5)
    //
    // Creation, listing and revocation are org-scoped as usual: it is *this*
    // org's hardware being shared, so this org's admins own the lifecycle.
    // Only [`Db::grants_for_subject`] — the read on the receiving side — leaves
    // the scope, for the reason documented there.
    // -----------------------------------------------------------------------

    /// Insert a grant of this org's hardware to `subject`.
    ///
    /// `selector` must be the **canonical rendering** of a
    /// [`fleet_proto::lease::Constraint`] (its `Display`), because evaluation
    /// re-parses it: storing whatever the user typed would let a grant's
    /// meaning depend on which CLI wrote it. `ops` is stored newline-joined,
    /// matching the `auth_key.tags` convention in this schema.
    ///
    /// # Errors
    ///
    /// Returns a database error if the insert fails (including the foreign key
    /// on a nonexistent org).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_grant(
        &self,
        id: &str,
        subject: &SubjectKey,
        selector: &str,
        ops: &[AllowedOp],
        expires: Option<i64>,
        created_by: Option<&str>,
        created_at: i64,
    ) -> Result<()> {
        let ops: Vec<&str> = ops.iter().map(|o| o.as_str()).collect();
        sqlx::query(
            "INSERT INTO \"grant\" (id, org_id, subject, selector, ops, expires, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(id)
        .bind(self.org.0.as_str())
        .bind(subject.to_string())
        .bind(selector)
        .bind(ops.join("\n"))
        .bind(expires)
        .bind(created_by)
        .bind(created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Insert a grant, replacing any row with the same id.
    ///
    /// The auth-key CI path's write (architecture §6.7): a multi-use key is
    /// redeemed by however many runners, and each redemption must converge on
    /// **one** grant row rather than accumulating a row per runner. The id is
    /// derived deterministically from the key hash, so "same key" is "same
    /// row".
    ///
    /// Deliberately separate from [`OrgDb::insert_grant`] rather than making
    /// that one upsert: a human-created grant colliding on id would be a bug
    /// worth failing on, and silently overwriting one is exactly the behaviour
    /// a security verb must not have.
    ///
    /// # Errors
    ///
    /// Returns a database error if the write fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_grant(
        &self,
        id: &str,
        subject: &SubjectKey,
        selector: &str,
        ops: &[AllowedOp],
        expires: Option<i64>,
        created_by: Option<&str>,
        created_at: i64,
    ) -> Result<()> {
        let ops: Vec<&str> = ops.iter().map(|o| o.as_str()).collect();
        sqlx::query(
            "INSERT INTO \"grant\" (id, org_id, subject, selector, ops, expires, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               selector = excluded.selector,
               ops      = excluded.ops,
               expires  = excluded.expires",
        )
        .bind(id)
        .bind(self.org.0.as_str())
        .bind(subject.to_string())
        .bind(selector)
        .bind(ops.join("\n"))
        .bind(expires)
        .bind(created_by)
        .bind(created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Every member of this org, with their role and cached login.
    ///
    /// New for the browser API (`GET /api/v1/org/members`); membership is
    /// **read-only** in v1, so there is deliberately no counterpart that
    /// writes. Lives on [`OrgDb`] rather than [`Db`] even though `member` is
    /// keyed `(org_id, user_id)` and a `Db` method could take the org as an
    /// argument: an org-taking method on `Db` is a call site that can be
    /// handed the wrong org, and the whole point of the handle is that it
    /// cannot.
    ///
    /// `login` is `user.login`, which is a **cache for display** and never an
    /// identity key (see [`Db::upsert_github_user`]); it is `NULL` for a user
    /// created by the interim `coordinator user-token` verb, so it stays an
    /// `Option` all the way to the JSON rather than being defaulted to the id.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn list_members(&self) -> Result<Vec<MemberRow>> {
        let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
            "SELECT member.user_id, user.login, member.role
             FROM member JOIN user ON user.id = member.user_id
             WHERE member.org_id = ?1 ORDER BY member.user_id",
        )
        .bind(self.org.0.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(user_id, login, role)| MemberRow {
                user_id,
                login,
                // An unparseable role is `Member`, the *lesser* of the two:
                // this is a listing, and a display that guessed `admin` would
                // be the one guess with a consequence.
                role: Role::from_label(&role).unwrap_or(Role::Member),
            })
            .collect())
    }

    /// Every node in this org, with its board names.
    ///
    /// New for the browser API (`GET /api/v1/nodes`); there is no wire verb for
    /// it — `ctl list` is board-shaped, and a machine that has plugged in no
    /// probes is invisible to it.
    ///
    /// Two rows-per-node deliberately are **not** joined into one query: the
    /// board join would multiply the node columns by the board count and make
    /// `last_seen` arrive once per board. Two statements, assembled here.
    ///
    /// `online` is not a column and is not answered here: liveness lives in the
    /// in-memory [`crate::registry::AgentRegistry`], and a database column that
    /// tried to track it would be wrong every time a process died. The caller
    /// composes the two.
    ///
    /// One honest wart, reported rather than papered over: [`OrgDb::ensure_node`]
    /// — the inventory-report path, which runs for a node that reports before
    /// it is registered — writes the **full node id** into `name`, because at
    /// that point it has an [`AgentId`] and nothing else. Every registration
    /// path ([`Db::register_node`], [`Db::register_node_full`]) writes the
    /// node-local name, and `ensure_node`'s `ON CONFLICT` leaves an existing
    /// row's `name` alone, so a machine that enrolled properly is unaffected.
    /// Normalising it here would be a listing that disagreed with the column;
    /// fixing the column is a migration, and this listing is not the place to
    /// smuggle one in.
    ///
    /// # Errors
    ///
    /// Returns a database error if either query fails, or
    /// [`CoordinatorError::State`](crate::error::CoordinatorError::State) if a
    /// stored `adopt_policy` is unrecognised — the same loud failure
    /// [`Db::node_org_and_policy`] takes, and for the same reason.
    pub async fn list_nodes(&self) -> Result<Vec<NodeRow>> {
        let rows: Vec<NodeDbRow> = sqlx::query_as(
            "SELECT id, name, tags, owner_user_id, adopt_policy, last_seen, created_at
             FROM node WHERE org_id = ?1 ORDER BY name",
        )
        .bind(self.org.0.as_str())
        .fetch_all(self.db.pool())
        .await?;

        let boards: Vec<(String, String)> =
            sqlx::query_as("SELECT node_id, name FROM board WHERE org_id = ?1 ORDER BY name")
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
                id: AgentId(id),
                name,
                tags: split_tags(&tags),
                owner_user_id: owner,
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
    /// The browser API addresses nodes by `name` (`UNIQUE (org_id, name)`)
    /// because the id contains a slash and cannot go in a URL path
    /// (`docs/web-ui.md` §3). Scoped through [`OrgDb`], so a name that exists
    /// only in another tenant resolves to `None` — which is what makes
    /// "another org's node" and "no such node" the same answer at the handler.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails, or
    /// [`CoordinatorError::State`](crate::error::CoordinatorError::State) if
    /// the stored `adopt_policy` is unrecognised, exactly as
    /// [`OrgDb::list_nodes`] does.
    pub async fn node_by_name(&self, name: &str) -> Result<Option<NodeRow>> {
        let row: Option<NodeDbRow> = sqlx::query_as(
            "SELECT id, name, tags, owner_user_id, adopt_policy, last_seen, created_at
             FROM node WHERE org_id = ?1 AND name = ?2",
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
            "SELECT name FROM board WHERE org_id = ?1 AND node_id = ?2 ORDER BY name",
        )
        .bind(self.org.0.as_str())
        .bind(id.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(Some(NodeRow {
            id: AgentId(id),
            name,
            tags: split_tags(&tags),
            owner_user_id: owner,
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
              WHERE org_id = ?1 AND name = ?2",
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
            sqlx::query_as("SELECT id FROM node WHERE org_id = ?1 AND name = ?2")
                .bind(self.org.0.as_str())
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(false);
        };
        sqlx::query("DELETE FROM board WHERE org_id = ?1 AND node_id = ?2")
            .bind(self.org.0.as_str())
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM node WHERE org_id = ?1 AND id = ?2")
            .bind(self.org.0.as_str())
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted > 0)
    }

    /// Every grant this org has issued, newest first.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub async fn list_grants(&self) -> Result<Vec<GrantRow>> {
        let rows: Vec<GrantDbRow> = sqlx::query_as(
            "SELECT id, org_id, subject, selector, ops, expires, created_by, created_at
             FROM \"grant\" WHERE org_id = ?1 ORDER BY created_at DESC",
        )
        .bind(self.org.0.as_str())
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(GrantRow::from_row).collect())
    }

    /// Delete this org's grants whose id starts with `prefix`, returning the
    /// rows deleted.
    ///
    /// Mirrors [`Db::delete_auth_keys_by_prefix`] so `grant revoke <id-prefix>`
    /// behaves like `auth-key revoke`, and returns the **whole rows** rather
    /// than the ids: the caller needs the subject and selector to drive the
    /// revocation cascade (tear down what the grantee is still holding).
    ///
    /// As there, the caller must refuse a too-short or ambiguous prefix
    /// *before* calling: an empty prefix is `LIKE '%'`, i.e. every grant in the
    /// org.
    ///
    /// # Errors
    ///
    /// Returns a database error if the delete fails.
    pub async fn delete_grants_by_prefix(&self, prefix: &str) -> Result<Vec<GrantRow>> {
        let rows: Vec<GrantDbRow> = sqlx::query_as(
            "DELETE FROM \"grant\" WHERE org_id = ?1 AND id LIKE ?2 || '%'
             RETURNING id, org_id, subject, selector, ops, expires, created_by, created_at",
        )
        .bind(self.org.0.as_str())
        .bind(prefix)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(GrantRow::from_row).collect())
    }
}

/// One row of [`OrgDb::list_members`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// The member's immutable user id.
    pub user_id: String,
    /// The cached GitHub login, for display only. `None` for a user created by
    /// the interim `coordinator user-token` verb.
    pub login: Option<String>,
    /// The role held in this org.
    pub role: Role,
}

/// One row of [`OrgDb::list_nodes`].
///
/// Deliberately not a `fleet-proto` type: nothing on the wire carries a node
/// listing, and inventing one in the shared crate for the sake of one HTTP
/// endpoint would put a browser-shaped struct where the postcard protocol
/// lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRow {
    /// The node's fleet id (`{org}/{name}`).
    pub id: AgentId,
    /// The node-local name, `UNIQUE (org_id, name)`.
    pub name: String,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// The owning user, if the node was enrolled by a logged-in human. `None`
    /// for an auth-key enrollment, which has no owning human by construction.
    pub owner_user_id: Option<String>,
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
/// Deterministic on purpose: re-running `share` / `agent up` on the same
/// machine re-enrolls that node (replacing its token) instead of littering the
/// org with duplicate rows for one physical Pi. The id is namespaced by org so
/// the same node name in two tenants is two nodes.
///
/// `pub(crate)` rather than private so the crate's unit-test fixtures can mint
/// node ids by *calling* it instead of re-implementing the format string. A
/// fixture that hand-rolls a domain identifier is a second, unversioned
/// definition of it, and it drifts: `core.rs`'s board fixture built bare ids
/// (`"node-a"`) for long enough that every qualified-name resolution test
/// passed while addressing boards production cannot produce.
pub(crate) fn node_id_for(org: &OrgId, name: &str) -> AgentId {
    AgentId(format!("{}/{name}", org.0))
}

/// A fresh, opaque grant id: 16 random bytes as 32 lowercase hex characters.
///
/// Not a credential — a grant id is a handle, printed by `grant list` and used
/// by `grant revoke <prefix>` — but random rather than sequential so an id
/// leaks nothing about how many grants the fleet has, and so prefixes stay
/// well distributed.
#[must_use]
pub fn new_grant_id() -> String {
    use rand_core::RngCore as _;
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
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
            model: None,
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
        // Two: the default org, plus the reserved `gha` namespace migration
        // 0007 creates (kind `system`, member of nothing) so that the
        // audit-log foreign key holds on every path that can be reached with a
        // workload subject. See that migration's header.
        assert_eq!(row.0, 2);
        let (kind,): (String,) = sqlx::query_as("SELECT kind FROM org WHERE id = 'gha'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(kind, "system");
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let db = Db::connect_in_memory().await.unwrap();
        // A board for a node that does not exist must be refused, not silently
        // accepted — this is what makes `ensure_node` load-bearing.
        let err = db
            .scoped(org(DEFAULT_ORG_ID))
            .record_board(&board_in(DEFAULT_ORG_ID, "ghost", "b1"), BoardPresence::Online, 1000)
            .await;
        assert!(err.is_err(), "FK must reject a board with no node row");
    }

    #[tokio::test]
    async fn ensure_node_then_record_board_persists() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        let scoped = db.scoped(o);
        scoped
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "b1"), BoardPresence::Online, 1000)
            .await
            .unwrap();
        // Upsert: same key again with a later timestamp.
        scoped
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "b1"), BoardPresence::Online, 2000)
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

    /// [`OrgDb::prune_boards`] is a set difference, and the set it applies to
    /// is exactly one node of one org.
    ///
    /// Also pins the empty-`keep` path: an agent that reports an empty
    /// inventory declares nothing, so all of *its* rows go — and the statement
    /// must degenerate to a plain `DELETE` rather than an invalid `NOT IN ()`.
    #[tokio::test]
    async fn prune_boards_is_scoped_to_one_node_and_one_org() {
        let db = Db::connect_in_memory().await.unwrap();
        let mine = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        db.scoped(mine.clone())
            .ensure_node(&AgentId("rpi-2".to_owned()), 1000)
            .await
            .unwrap();
        let theirs = seeded(&db, "other", "rpi-9").await;
        for (o, node, name) in [
            (&mine, "rpi-1", "b1"),
            (&mine, "rpi-1", "b2"),
            (&mine, "rpi-2", "b1"),
            (&theirs, "rpi-9", "b1"),
        ] {
            db.scoped(o.clone())
                .record_board(&board_in(&o.0, node, name), BoardPresence::Online, 1000)
                .await
                .unwrap();
        }

        // A rename: `rpi-1` now declares only `b2`.
        let deleted = db
            .scoped(mine.clone())
            .prune_boards(&AgentId("rpi-1".to_owned()), &["b2".to_owned()])
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        assert!(!db
            .scoped(mine.clone())
            .has_board(&board_ref(DEFAULT_ORG_ID, "rpi-1", "b1"))
            .await
            .unwrap());
        assert!(db
            .scoped(mine.clone())
            .has_board(&board_ref(DEFAULT_ORG_ID, "rpi-1", "b2"))
            .await
            .unwrap());
        // The sibling node and the other tenant are untouched.
        assert!(db
            .scoped(mine.clone())
            .has_board(&board_ref(DEFAULT_ORG_ID, "rpi-2", "b1"))
            .await
            .unwrap());
        assert_eq!(db.scoped(theirs.clone()).board_count().await.unwrap(), 1);

        // Empty keep-set: every row of that node goes, and only that node's.
        let deleted = db
            .scoped(mine.clone())
            .prune_boards(&AgentId("rpi-1".to_owned()), &[])
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.scoped(mine).board_count().await.unwrap(), 1, "rpi-2's row survives");
        assert_eq!(db.scoped(theirs).board_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn record_board_refuses_a_foreign_org_board() {
        let db = Db::connect_in_memory().await.unwrap();
        let a = seeded(&db, "org-a", "rpi-1").await;
        seeded(&db, "org-b", "rpi-2").await;
        let err = db
            .scoped(a)
            .record_board(&board_in("org-b", "rpi-2", "b1"), BoardPresence::Online, 1000)
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

        da.record_board(&board_in("org-a", "node-a", "dk"), BoardPresence::Online, 1000)
            .await
            .unwrap();
        db_.record_board(&board_in("org-b", "node-b", "dk"), BoardPresence::Online, 1000)
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
            .record_board(&board_in("org-a", "node-a", "dk"), BoardPresence::Online, 1000)
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
        db.insert_auth_key(
            &o,
            "hash-a",
            &["nrf52".to_owned()],
            true,
            Some(2000),
            Some("root"),
            1000,
        )
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
            .record_board(&board_in(DEFAULT_ORG_ID, "agent-a", "b1"), BoardPresence::Online, 1000)
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

    /// `ensure_node` runs on every inventory report, so it must create a row
    /// the policy parser accepts. `0001_init.sql`'s column default is the
    /// retired placeholder `'manual'`, which `AdoptPolicy::from_label` rejects
    /// — so a row that let the default apply would fail the lookup on the very
    /// next report.
    #[tokio::test]
    async fn ensure_node_creates_a_row_with_a_parseable_policy() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        assert_eq!(
            db.node_org_and_policy(&AgentId("agent-a".to_owned()))
                .await
                .unwrap(),
            Some((o, AdoptPolicy::Declared)),
            "an implicitly created node is conservative, and parseable"
        );
    }

    /// The crux of the `ensure_node` / `register_node_full` split: an inventory
    /// report must never reset a `share`-created node to `declared`, which is
    /// what would happen if `ensure_node`'s `ON CONFLICT` touched the column.
    #[tokio::test]
    async fn ensure_node_does_not_overwrite_a_registered_policy() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.ensure_org(&o, "personal").await.unwrap();
        db.ensure_user_member(&o, "alice", Role::Admin)
            .await
            .unwrap();
        let node = db
            .register_node_full(
                &o,
                "laptop",
                "hash",
                &[],
                Some("alice"),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();

        for _ in 0..3 {
            db.scoped(o.clone()).ensure_node(&node, 2000).await.unwrap();
        }

        assert_eq!(
            db.node_org_and_policy(&node).await.unwrap(),
            Some((o, AdoptPolicy::Auto))
        );
        assert_eq!(db.node_owner(&node).await.unwrap().as_deref(), Some("alice"));
    }

    /// A machine enrolled from an image and later shared by its owner must
    /// converge on the latest registration, rather than keeping a stale policy
    /// nobody can see.
    #[tokio::test]
    async fn re_registering_converges_on_the_latest_owner_and_policy() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.ensure_org(&o, "personal").await.unwrap();
        db.ensure_user_member(&o, "alice", Role::Admin).await.unwrap();

        // Auth-key enrollment: unowned, `declared`.
        let node = db
            .register_node(&o, "laptop", "hash-1", &["lab".to_owned()], 1000)
            .await
            .unwrap();
        assert!(db.node_owner(&node).await.unwrap().is_none());
        assert_eq!(
            db.node_org_and_policy(&node).await.unwrap().unwrap().1,
            AdoptPolicy::Declared
        );

        // ...then `share`: same id (one physical machine, one row), now owned
        // and auto-adopting.
        let again = db
            .register_node_full(
                &o,
                "laptop",
                "hash-2",
                &[],
                Some("alice"),
                AdoptPolicy::Auto,
                2000,
            )
            .await
            .unwrap();
        assert_eq!(again, node, "one machine must not become two rows");
        assert_eq!(
            db.node_owner(&node).await.unwrap().as_deref(),
            Some("alice")
        );
        assert_eq!(
            db.node_org_and_policy(&node).await.unwrap().unwrap().1,
            AdoptPolicy::Auto
        );
    }

    /// An unrecognised stored policy must fail loudly. Treating it as `auto`
    /// would adopt probes nobody asked to share; treating it as `declared`
    /// would silently disable a feature its owner turned on.
    #[tokio::test]
    async fn an_unrecognised_stored_policy_is_an_error_not_a_default() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        sqlx::query("UPDATE node SET adopt_policy = 'manual' WHERE id = ?1")
            .bind("agent-a")
            .execute(db.pool())
            .await
            .unwrap();
        let _ = o;

        let err = db
            .node_org_and_policy(&AgentId("agent-a".to_owned()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::error::CoordinatorError::State(_)),
            "got {err:?}"
        );
    }

    /// Auth keys are listable so that "revocable" is true in practice: an
    /// operator who has lost track of which images carry which key can see
    /// what is outstanding. The listing is hash-only, so it is safe to print.
    #[tokio::test]
    async fn auth_keys_are_listable_and_revocable_by_prefix() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        let other = org("other");
        db.ensure_org(&o, "personal").await.unwrap();
        db.ensure_org(&other, "team").await.unwrap();

        db.insert_auth_key(
            &o,
            "aaaa1111",
            &["lab".to_owned()],
            true,
            Some(9_999),
            Some("alice"),
            1000,
        )
        .await
        .unwrap();
        db.insert_auth_key(&o, "bbbb2222", &[], false, None, None, 1001)
            .await
            .unwrap();
        // Another org's key must not appear, or be revocable from here.
        db.insert_auth_key(&other, "aaaa9999", &[], true, None, None, 1002)
            .await
            .unwrap();

        let keys = db.list_auth_keys(&o).await.unwrap();
        assert_eq!(keys.len(), 2, "only this org's keys");
        // Newest first, so the key an operator just minted is at the top.
        assert_eq!(keys[0].key_hash, "bbbb2222");
        assert!(!keys[0].single_use);
        assert!(keys[0].expires.is_none());
        assert_eq!(keys[1].tags, vec!["lab".to_owned()]);
        assert_eq!(keys[1].expires, Some(9_999));
        // `created_by` round-trips: it is what lets the API let a creator revoke
        // their own key, and distinguishes a shell-minted key (NULL) from a
        // member-minted one.
        assert_eq!(keys[1].created_by.as_deref(), Some("alice"));
        assert!(keys[0].created_by.is_none());

        let deleted = db.delete_auth_keys_by_prefix(&o, "aaaa").await.unwrap();
        assert_eq!(deleted, vec!["aaaa1111".to_owned()]);
        assert_eq!(db.list_auth_keys(&o).await.unwrap().len(), 1);
        // Tenancy: the other org's similarly-prefixed key is untouched.
        assert_eq!(db.list_auth_keys(&other).await.unwrap().len(), 1);

        // A revoked key stops being redeemable, which is the point.
        assert!(db
            .consume_auth_key("aaaa1111", 1_500)
            .await
            .unwrap()
            .is_none());
    }

    /// A named `ci` key's identity round-trips through both read paths, and an
    /// unnamed one reads back as `None` — not `Some("")`, which migration 0009
    /// exists to make unrepresentable.
    #[tokio::test]
    async fn an_auth_keys_identity_name_round_trips_and_absence_is_null() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.ensure_org(&o, "personal").await.unwrap();

        db.insert_auth_key_with_purpose(
            &o,
            "named111",
            &["lab".to_owned()],
            false,
            Some(9_999),
            Some("alice"),
            1_000,
            AUTH_KEY_PURPOSE_CI,
            &[],
            Some("builder"),
        )
        .await
        .unwrap();
        db.insert_auth_key_with_purpose(
            &o,
            "plain222",
            &["lab".to_owned()],
            false,
            Some(9_999),
            None,
            1_001,
            AUTH_KEY_PURPOSE_CI,
            &[],
            None,
        )
        .await
        .unwrap();

        let named = db.ci_auth_key_meta("named111").await.unwrap().unwrap();
        assert_eq!(named.subject_name.as_deref(), Some("builder"));
        let plain = db.ci_auth_key_meta("plain222").await.unwrap().unwrap();
        assert_eq!(plain.subject_name, None);

        let keys = db.list_auth_keys(&o).await.unwrap();
        let by_hash = |h: &str| {
            keys.iter()
                .find(|k| k.key_hash == h)
                .expect("the key is listed")
                .subject_name
                .clone()
        };
        assert_eq!(by_hash("named111").as_deref(), Some("builder"));
        assert_eq!(by_hash("plain222"), None);

        // The node-enrollment spelling stores no name, so every pre-0009 row
        // and every node key keeps the hash-derived meaning.
        db.insert_auth_key(&o, "node3333", &[], true, None, None, 1_002)
            .await
            .unwrap();
        assert_eq!(by_hash("named111").as_deref(), Some("builder"));
        assert_eq!(
            db.ci_auth_key_meta("node3333")
                .await
                .unwrap()
                .unwrap()
                .subject_name,
            None
        );
    }

    /// Seed a pending registration with a fixed code, for the state-machine
    /// tests below.
    async fn seed_pending(db: &Db, code: &str, hash: &str, name: &str, expires: i64) {
        db.insert_pending_node(
            || code.to_owned(),
            hash,
            name,
            &["lab".to_owned()],
            AdoptPolicy::Auto,
            Some("203.0.113.7"),
            1_000,
            expires,
        )
        .await
        .unwrap();
    }

    /// The happy path, and the single-use property that makes it safe:
    /// approve, redeem once, and a second redemption mints nothing.
    #[tokio::test]
    async fn pending_node_approve_then_consume_exactly_once() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.ensure_user_member(&o, "alice", Role::Member)
            .await
            .unwrap();
        seed_pending(&db, "ABCD1234", "hash-a", "rpi-lab-3", 2_000).await;

        let pending = db
            .pending_node_by_code("ABCD1234", 1_100)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.is_pending());
        assert_eq!(pending.state_label(), "pending");
        assert_eq!(pending.node_name, "rpi-lab-3");
        assert_eq!(pending.tags, vec!["lab".to_owned()]);
        assert_eq!(pending.adopt, AdoptPolicy::Auto);
        assert_eq!(pending.source_ip.as_deref(), Some("203.0.113.7"));
        assert!(pending.org.is_none(), "no org until it is decided");

        // Not redeemable before approval.
        assert!(db
            .consume_pending_node("hash-a", 1_100)
            .await
            .unwrap()
            .is_none());

        assert!(db
            .approve_pending_node("ABCD1234", &o, "alice", 1_200)
            .await
            .unwrap());
        // A second approval binds nothing: one conditional UPDATE is what stops
        // two approvers landing the machine in two orgs.
        let other = org("other");
        db.ensure_org(&other, "personal").await.unwrap();
        assert!(!db
            .approve_pending_node("ABCD1234", &other, "mallory", 1_250)
            .await
            .unwrap());

        let (bound_org, approver, name, tags, adopt) = db
            .consume_pending_node("hash-a", 1_300)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bound_org, o);
        assert_eq!(approver, "alice");
        assert_eq!(name, "rpi-lab-3");
        assert_eq!(tags, vec!["lab".to_owned()]);
        assert_eq!(adopt, AdoptPolicy::Auto);

        // The single atomic consume: a racing second poll mints nothing.
        assert!(db
            .consume_pending_node("hash-a", 1_300)
            .await
            .unwrap()
            .is_none());
    }

    /// Denial is permanent, and is "consumed without ever being approved" —
    /// the property the schema encodes without a `denied_at` column.
    #[tokio::test]
    async fn pending_node_denial_is_final() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.ensure_user_member(&o, "alice", Role::Member)
            .await
            .unwrap();
        seed_pending(&db, "ABCD1234", "hash-a", "rpi", 2_000).await;

        assert!(db.deny_pending_node("ABCD1234", 1_200).await.unwrap());
        let pending = db
            .pending_node_by_code("ABCD1234", 1_300)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.is_denied());
        assert_eq!(pending.state_label(), "denied");

        // Neither approvable nor redeemable afterwards.
        assert!(!db
            .approve_pending_node("ABCD1234", &o, "alice", 1_400)
            .await
            .unwrap());
        assert!(db
            .consume_pending_node("hash-a", 1_400)
            .await
            .unwrap()
            .is_none());
        assert!(!db.deny_pending_node("ABCD1234", 1_400).await.unwrap());
    }

    /// Expiry is enforced by the statements themselves, not by the sweep.
    #[tokio::test]
    async fn pending_node_expiry_is_enforced_at_every_transition() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.ensure_user_member(&o, "alice", Role::Member)
            .await
            .unwrap();
        seed_pending(&db, "ABCD1234", "hash-a", "rpi", 2_000).await;

        // Boundary: expiry is exclusive, matching session verification.
        assert!(db
            .pending_node_by_code("ABCD1234", 2_000)
            .await
            .unwrap()
            .is_none());
        assert!(!db
            .approve_pending_node("ABCD1234", &o, "alice", 2_000)
            .await
            .unwrap());
        assert!(!db.deny_pending_node("ABCD1234", 2_000).await.unwrap());

        // Approved before expiry, redeemed after: still refused.
        assert!(db
            .approve_pending_node("ABCD1234", &o, "alice", 1_500)
            .await
            .unwrap());
        assert!(db
            .consume_pending_node("hash-a", 2_100)
            .await
            .unwrap()
            .is_none());
    }

    /// The listing a `node list-pending` verb (and the e2e test) needs: live
    /// rows only, newest first.
    #[tokio::test]
    async fn live_pending_codes_excludes_spent_and_expired_rows() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.ensure_user_member(&o, "alice", Role::Member)
            .await
            .unwrap();
        seed_pending(&db, "AAAA1111", "hash-a", "live", 2_000).await;
        seed_pending(&db, "BBBB2222", "hash-b", "denied", 2_000).await;
        seed_pending(&db, "CCCC3333", "hash-c", "expired", 1_050).await;
        db.deny_pending_node("BBBB2222", 1_100).await.unwrap();

        let live = db.live_pending_codes(1_200).await.unwrap();
        assert_eq!(live, vec![("AAAA1111".to_owned(), "live".to_owned())]);
        assert_eq!(db.live_pending_node_count(1_200).await.unwrap(), 1);

        // The sweep is hygiene: it removes the spent and expired rows the
        // statements above already refuse to act on.
        assert_eq!(db.delete_expired_pending_nodes(1_200).await.unwrap(), 2);
        assert_eq!(db.live_pending_codes(1_200).await.unwrap().len(), 1);
    }

    /// A code collision must not surface as an unhandled error on an
    /// unauthenticated route: the insert retries with a fresh code.
    #[tokio::test]
    async fn insert_pending_node_retries_past_a_code_collision() {
        let db = Db::connect_in_memory().await.unwrap();
        seed_pending(&db, "AAAA1111", "hash-a", "first", 2_000).await;

        let mut codes = ["AAAA1111", "AAAA1111", "BBBB2222"].into_iter();
        let code = db
            .insert_pending_node(
                || codes.next().unwrap().to_owned(),
                "hash-b",
                "second",
                &[],
                AdoptPolicy::Declared,
                None,
                1_000,
                2_000,
            )
            .await
            .unwrap();
        assert_eq!(code, "BBBB2222");

        // Three collisions in a row is an error, not an infinite loop.
        assert!(db
            .insert_pending_node(
                || "AAAA1111".to_owned(),
                "hash-c",
                "third",
                &[],
                AdoptPolicy::Declared,
                None,
                1_000,
                2_000,
            )
            .await
            .is_err());
    }

    /// The collision check the approval path refuses on.
    #[tokio::test]
    async fn node_id_in_org_by_name_is_org_scoped() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        let other = seeded(&db, "other", "agent-b").await;
        db.register_node(&o, "rpi-lab-3", "hash", &[], 1_000)
            .await
            .unwrap();

        assert_eq!(
            db.node_id_in_org_by_name(&o, "rpi-lab-3").await.unwrap(),
            Some(format!("{DEFAULT_ORG_ID}/rpi-lab-3"))
        );
        assert!(db
            .node_id_in_org_by_name(&o, "rpi-lab-4")
            .await
            .unwrap()
            .is_none());
        // The same name in another tenant is another node, not a collision.
        assert!(db
            .node_id_in_org_by_name(&other, "rpi-lab-3")
            .await
            .unwrap()
            .is_none());
    }

    /// The two browser-API listings are scoped by the `OrgDb` handle, which is
    /// the property that makes "no code path can forget the org check" true
    /// rather than aspirational.
    #[tokio::test]
    async fn member_and_node_listings_are_org_scoped() {
        let db = Db::connect_in_memory().await.unwrap();
        let mine = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        let theirs = seeded(&db, "other", "rpi-2").await;

        db.ensure_user_member(&mine, "alice", Role::Admin)
            .await
            .unwrap();
        db.ensure_user_member(&mine, "bob", Role::Member)
            .await
            .unwrap();
        db.ensure_user_member(&theirs, "mallory", Role::Admin)
            .await
            .unwrap();

        let members = db.scoped(mine.clone()).list_members().await.unwrap();
        let ids: Vec<&str> = members.iter().map(|m| m.user_id.as_str()).collect();
        assert_eq!(ids, ["alice", "bob"]);
        assert_eq!(members[0].role, Role::Admin);
        assert_eq!(members[1].role, Role::Member);
        // `user-token`-created users carry no login; it stays absent rather
        // than being defaulted to the id.
        assert_eq!(members[0].login, None);

        let mine_nodes = db.scoped(mine.clone()).list_nodes().await.unwrap();
        assert_eq!(mine_nodes.len(), 1);
        assert_eq!(mine_nodes[0].name, "rpi-1");
        assert_eq!(mine_nodes[0].boards, Vec::<String>::new());

        // The other tenant's node is not merely filtered out of the listing:
        // it is unreachable through this handle at all.
        let their_nodes = db.scoped(theirs).list_nodes().await.unwrap();
        assert_eq!(their_nodes.len(), 1);
        assert_eq!(their_nodes[0].name, "rpi-2");
    }

    /// A node's boards come back with it, and a board of another org's node
    /// never attaches to this one.
    #[tokio::test]
    async fn node_listing_carries_its_boards() {
        let db = Db::connect_in_memory().await.unwrap();
        let mine = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        let theirs = seeded(&db, "other", "rpi-2").await;
        db.scoped(mine.clone())
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "dk-1"), BoardPresence::Online, 10)
            .await
            .unwrap();
        db.scoped(mine.clone())
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "dk-2"), BoardPresence::Online, 10)
            .await
            .unwrap();
        db.scoped(theirs)
            .record_board(&board_in("other", "rpi-2", "dk-1"), BoardPresence::Online, 10)
            .await
            .unwrap();

        let nodes = db.scoped(mine).list_nodes().await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].boards, ["dk-1", "dk-2"]);
    }

    /// An unparseable `adopt_policy` is an error, not a default — the same
    /// loud failure `node_org_and_policy` takes, for the same reason: guessing
    /// `auto` would report probes as adoptable that nobody shared.
    #[tokio::test]
    async fn node_listing_refuses_an_unknown_adopt_policy() {
        let db = Db::connect_in_memory().await.unwrap();
        let org = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        sqlx::query("UPDATE node SET adopt_policy = 'sometimes' WHERE org_id = ?1")
            .bind(DEFAULT_ORG_ID)
            .execute(db.pool_for_test())
            .await
            .unwrap();
        assert!(db.scoped(org).list_nodes().await.is_err());
    }

    /// `node_by_name` is the browser API's lookup, and its tenancy is the
    /// `OrgDb` handle's: the *same* name in another org is `None`, not a
    /// different tenant's row. That is what lets the handler answer "no such
    /// node" and "not yours" identically without having to remember to.
    #[tokio::test]
    async fn node_by_name_is_org_scoped() {
        let db = Db::connect_in_memory().await.unwrap();
        let mine = org(DEFAULT_ORG_ID);
        let theirs = org("other");
        db.ensure_org(&mine, "personal").await.unwrap();
        db.ensure_org(&theirs, "personal").await.unwrap();
        db.register_node(&mine, "rpi", "h-a", &[], 10)
            .await
            .unwrap();
        db.register_node(&theirs, "rpi", "h-b", &[], 10)
            .await
            .unwrap();

        let found = db.scoped(mine.clone()).node_by_name("rpi").await.unwrap();
        assert_eq!(found.as_ref().map(|n| n.id.0.as_str()), Some("default/rpi"));
        assert!(db
            .scoped(mine.clone())
            .node_by_name("absent")
            .await
            .unwrap()
            .is_none());
        // The other tenant's identically-named node is invisible, not merely
        // filtered: this handle cannot express a query that reaches it.
        assert_eq!(
            db.scoped(theirs)
                .node_by_name("rpi")
                .await
                .unwrap()
                .map(|n| n.id.0),
            Some("other/rpi".to_owned())
        );
    }

    /// `update_node` writes only what it was asked to: `None` leaves a column
    /// alone, `Some(vec![])` clears the tags, and the **name never moves** —
    /// there is no parameter for it, because the id is a foreign key target.
    #[tokio::test]
    async fn update_node_is_partial_and_never_renames() {
        let db = Db::connect_in_memory().await.unwrap();
        let o = org(DEFAULT_ORG_ID);
        db.ensure_org(&o, "personal").await.unwrap();
        db.register_node_full(
            &o,
            "rpi",
            "h",
            &["lab".to_owned()],
            None,
            AdoptPolicy::Declared,
            10,
        )
        .await
        .unwrap();
        let scoped = db.scoped(o.clone());

        // Adopt only: the tags survive.
        let row = scoped
            .update_node("rpi", None, Some(AdoptPolicy::Auto))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.adopt, AdoptPolicy::Auto);
        assert_eq!(row.tags, ["lab"]);

        // Tags only: the policy survives.
        let row = scoped
            .update_node("rpi", Some(&["a".to_owned(), "b".to_owned()]), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.tags, ["a", "b"]);
        assert_eq!(row.adopt, AdoptPolicy::Auto);

        // An empty list clears; `None` would not have.
        let row = scoped
            .update_node("rpi", Some(&[]), None)
            .await
            .unwrap()
            .unwrap();
        assert!(row.tags.is_empty());

        // Neither: a no-op that still reports the row.
        let row = scoped
            .update_node("rpi", None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.name, "rpi");
        assert_eq!(row.id.0, "default/rpi");

        // A name this org does not have is `None`, not an error.
        assert!(scoped
            .update_node("absent", None, None)
            .await
            .unwrap()
            .is_none());
    }

    /// The cascade `Db::delete_node` cannot do: `board.node_id REFERENCES
    /// node(id)` is enforced, so a bare node delete fails for any node that
    /// ever reported a board. This test would fail against that bare delete,
    /// which is the point of having it.
    #[tokio::test]
    async fn delete_node_cascades_to_its_boards() {
        let db = Db::connect_in_memory().await.unwrap();
        let mine = seeded(&db, DEFAULT_ORG_ID, "rpi-1").await;
        let theirs = seeded(&db, "other", "rpi-2").await;
        db.scoped(mine.clone())
            .record_board(&board_in(DEFAULT_ORG_ID, "rpi-1", "dk-1"), BoardPresence::Online, 10)
            .await
            .unwrap();
        db.scoped(theirs.clone())
            .record_board(&board_in("other", "rpi-2", "dk-1"), BoardPresence::Online, 10)
            .await
            .unwrap();

        // `ensure_node` writes the full id into `name` (see `list_nodes`), so
        // that is what this node is addressed by here.
        assert!(db.scoped(mine.clone()).delete_node("rpi-1").await.unwrap());
        assert!(db
            .scoped(mine.clone())
            .node_by_name("rpi-1")
            .await
            .unwrap()
            .is_none());
        let boards: Vec<(String,)> = sqlx::query_as("SELECT node_id FROM board")
            .fetch_all(db.pool_for_test())
            .await
            .unwrap();
        assert_eq!(boards, vec![("rpi-2".to_owned(),)], "only ours went");

        // Deleting again is `false`, not an error — and another org's node of
        // any name is not reachable through this handle.
        assert!(!db.scoped(mine.clone()).delete_node("rpi-1").await.unwrap());
        assert!(!db.scoped(mine).delete_node("rpi-2").await.unwrap());
        assert!(db
            .scoped(theirs)
            .node_by_name("rpi-2")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn file_backed_db_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coord.sqlite");
        let path_str = path.to_str().unwrap();
        let db = Db::connect(path_str).await.unwrap();
        let o = seeded(&db, DEFAULT_ORG_ID, "agent-a").await;
        db.scoped(o.clone())
            .record_board(&board_in(DEFAULT_ORG_ID, "agent-a", "b1"), BoardPresence::Online, 1000)
            .await
            .unwrap();
        drop(db);
        // Reopen and confirm persistence.
        let db = Db::connect(path_str).await.unwrap();
        assert_eq!(db.scoped(o).board_count().await.unwrap(), 1);
    }

    // -----------------------------------------------------------------------
    // Grants (architecture §6.5)
    // -----------------------------------------------------------------------

    fn subject_key(org_name: &str, id: &str) -> SubjectKey {
        SubjectKey {
            org: org(org_name),
            kind: fleet_proto::ids::SubjectKind::User,
            id: id.to_owned(),
        }
    }

    #[tokio::test]
    async fn grants_insert_list_and_revoke_by_prefix() {
        use fleet_proto::token::AllowedOp;

        let db = Db::connect_in_memory().await.unwrap();
        let a = org("org-a");
        let other = org("org-b");
        db.ensure_org(&a, "team").await.unwrap();
        db.ensure_org(&other, "team").await.unwrap();

        let bob = subject_key("gh-2", "gh-2");
        db.scoped(a.clone())
            .insert_grant(
                "aaaa1111",
                &bob,
                "tag=nrf52",
                &[AllowedOp::Flash, AllowedOp::Attach],
                Some(9_999),
                Some("gh-1"),
                1_000,
            )
            .await
            .unwrap();
        db.scoped(a.clone())
            .insert_grant("bbbb2222", &bob, "chip=nRF52840_xxAA", &[AllowedOp::Gdb], None, None, 1_001)
            .await
            .unwrap();
        // Another org's grant must neither list nor revoke from here.
        db.scoped(other.clone())
            .insert_grant("aaaa9999", &bob, "tag=nrf52", &[AllowedOp::Attach], None, None, 1_002)
            .await
            .unwrap();

        let grants = db.scoped(a.clone()).list_grants().await.unwrap();
        assert_eq!(grants.len(), 2, "only this org's grants");
        assert_eq!(grants[0].id, "bbbb2222", "newest first");
        assert_eq!(grants[1].selector, "tag=nrf52");
        assert_eq!(
            grants[1].parsed_ops(),
            vec![AllowedOp::Flash, AllowedOp::Attach]
        );
        assert_eq!(grants[1].parsed_subject(), Some(bob.clone()));
        assert_eq!(grants[1].created_by.as_deref(), Some("gh-1"));

        let deleted = db
            .scoped(a.clone())
            .delete_grants_by_prefix("aaaa")
            .await
            .unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].id, "aaaa1111");
        assert_eq!(db.scoped(a).list_grants().await.unwrap().len(), 1);
        // Tenancy: the other org's similarly-prefixed grant is untouched.
        assert_eq!(db.scoped(other).list_grants().await.unwrap().len(), 1);
    }

    /// `grants_for_subject` is the one query that deliberately leaves `OrgDb`.
    /// It must be scoped by the *subject* instead — tightly.
    #[tokio::test]
    async fn grants_for_subject_crosses_orgs_but_not_subjects() {
        use fleet_proto::token::AllowedOp;

        let db = Db::connect_in_memory().await.unwrap();
        for name in ["org-a", "org-c", "org-b"] {
            db.ensure_org(&org(name), "team").await.unwrap();
        }
        let bob = subject_key("gh-2", "gh-2");
        let mallory = subject_key("gh-3", "gh-3");

        db.scoped(org("org-a"))
            .insert_grant("g1", &bob, "tag=nrf52", &[AllowedOp::Attach], None, None, 1)
            .await
            .unwrap();
        db.scoped(org("org-c"))
            .insert_grant("g2", &bob, "tag=stm32", &[AllowedOp::Gdb], None, None, 2)
            .await
            .unwrap();
        db.scoped(org("org-a"))
            .insert_grant("g3", &mallory, "tag=nrf52", &[AllowedOp::Attach], None, None, 3)
            .await
            .unwrap();

        let mut ids: Vec<String> = db
            .grants_for_subject(&bob, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["g1".to_owned(), "g2".to_owned()], "both orgs, one subject");

        assert_eq!(db.grants_for_subject(&mallory, 100).await.unwrap().len(), 1);
        assert!(db
            .grants_for_subject(&subject_key("gh-9", "gh-9"), 100)
            .await
            .unwrap()
            .is_empty());
        // Same id in a different org is a different subject.
        assert!(db
            .grants_for_subject(&subject_key("org-z", "gh-2"), 100)
            .await
            .unwrap()
            .is_empty());
    }

    /// Expiry is filtered in SQL as well as in `Access`, so a stale row cannot
    /// widen access even if a caller forgets the clock.
    #[tokio::test]
    async fn grants_for_subject_filters_expired_rows() {
        use fleet_proto::token::AllowedOp;

        let db = Db::connect_in_memory().await.unwrap();
        db.ensure_org(&org("org-a"), "team").await.unwrap();
        let bob = subject_key("gh-2", "gh-2");
        db.scoped(org("org-a"))
            .insert_grant("g1", &bob, "tag=nrf52", &[AllowedOp::Attach], Some(500), None, 1)
            .await
            .unwrap();
        db.scoped(org("org-a"))
            .insert_grant("g2", &bob, "tag=lab", &[AllowedOp::Attach], None, None, 2)
            .await
            .unwrap();

        assert_eq!(db.grants_for_subject(&bob, 400).await.unwrap().len(), 2);
        let live = db.grants_for_subject(&bob, 600).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, "g2");
    }

    /// A row that no longer parses must fail closed. Notably an *unparseable
    /// selector* must never become "matches everything", and a row with no
    /// recognisable op confers nothing.
    #[tokio::test]
    async fn an_unusable_grant_row_yields_no_scope() {
        use fleet_proto::token::AllowedOp;

        let db = Db::connect_in_memory().await.unwrap();
        db.ensure_org(&org("org-a"), "team").await.unwrap();
        let bob = subject_key("gh-2", "gh-2");
        let scoped = db.scoped(org("org-a"));

        scoped
            .insert_grant("good", &bob, "tag=nrf52", &[AllowedOp::Attach], None, None, 1)
            .await
            .unwrap();
        // Written the way a bad migration or a hand-edit would leave it.
        for (id, selector, ops) in [
            ("empty-sel", "", "attach"),
            ("bad-sel", "colour=red", "attach"),
            ("no-ops", "tag=nrf52", ""),
            ("junk-ops", "tag=nrf52", "root"),
        ] {
            sqlx::query(
                "INSERT INTO \"grant\" (id, org_id, subject, selector, ops, expires, created_by, created_at)
                 VALUES (?1, 'org-a', ?2, ?3, ?4, NULL, NULL, 0)",
            )
            .bind(id)
            .bind(bob.to_string())
            .bind(selector)
            .bind(ops)
            .execute(db.pool_for_test())
            .await
            .unwrap();
        }

        let rows = db.grants_for_subject(&bob, 100).await.unwrap();
        assert_eq!(rows.len(), 5, "every row is still listable and revocable");
        let usable: Vec<_> = rows.iter().filter_map(GrantRow::to_scope).collect();
        assert_eq!(usable.len(), 1, "only the well-formed row confers access");
        assert_eq!(usable[0].id, "good");
    }

    /// Grant ids are opaque and unique enough that a prefix addresses one row.
    #[test]
    fn grant_ids_are_random_hex() {
        let a = new_grant_id();
        let b = new_grant_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b);
    }
}
