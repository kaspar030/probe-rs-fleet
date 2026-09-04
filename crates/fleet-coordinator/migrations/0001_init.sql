-- Coordinator persistent state, architecture revision 2 (§6.1).
--
-- Every object belongs to an org. Multi-tenancy here is a **security boundary
-- between paying customers**, not a tidiness property, so:
--   * every table a caller can reach carries `org_id`;
--   * the Rust `Db` API exposes those tables only through an `OrgDb` handle
--     that interpolates one org into every WHERE clause, so an unscoped query
--     is not expressible from outside `state.rs`;
--   * `PRAGMA foreign_keys = ON` is set on connect, so the REFERENCES below
--     are enforced rather than decorative.
--
-- The database is wiped for revision 2: this file replaces the revision-1
-- schema wholesale, there is no ALTER-TABLE migration path and none is wanted.

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

-- An org. A personal org (an org of one) is created on first login; there is
-- deliberately no user-owned/org-owned branch, so no code path can forget the
-- org check.
CREATE TABLE org (
    id          TEXT    NOT NULL PRIMARY KEY,
    slug        TEXT    NOT NULL UNIQUE,
    kind        TEXT    NOT NULL,              -- 'personal' | 'team'
    created_at  INTEGER NOT NULL               -- epoch seconds
);

-- A human. `github_user_id` is the immutable numeric id; `login` is cached for
-- display only and must never be used as an identity key (it can be renamed
-- and reused by someone else).
CREATE TABLE user (
    id              TEXT    NOT NULL PRIMARY KEY,
    personal_org_id TEXT    NOT NULL REFERENCES org(id),
    github_user_id  INTEGER,
    login           TEXT,
    email           TEXT,
    created_at      INTEGER NOT NULL           -- epoch seconds
);

-- Org membership. Two roles only (architecture §6.5): `member` may add a node
-- and use the org's boards; `admin` additionally acts on other members' leases
-- and reads the audit log.
--
-- Note membership is defined for users only: a `node` or `workload` subject has
-- no row here and is therefore denied by construction until grants land.
CREATE TABLE member (
    org_id  TEXT NOT NULL REFERENCES org(id),
    user_id TEXT NOT NULL REFERENCES user(id),
    role    TEXT NOT NULL,                     -- 'admin' | 'member'
    PRIMARY KEY (org_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Inventory
-- ---------------------------------------------------------------------------

-- A machine offering probes to the fleet.
--
-- `token_hash` is the lowercase-hex SHA-256 of the node's bearer token: the
-- secret itself is never stored. Revoking a node is deleting its row, which is
-- what makes revocation trivially auditable. `token_issued_at` drives the
-- rotation policy in `fleet-auth`.
CREATE TABLE node (
    id              TEXT    NOT NULL PRIMARY KEY,
    org_id          TEXT    NOT NULL REFERENCES org(id),
    owner_user_id   TEXT    REFERENCES user(id),
    name            TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '', -- newline-joined
    token_hash      TEXT,
    token_issued_at INTEGER,                     -- epoch seconds
    adopt_policy    TEXT    NOT NULL DEFAULT 'manual',
    last_seen       INTEGER,                     -- epoch seconds
    created_at      INTEGER NOT NULL,            -- epoch seconds
    UNIQUE (org_id, name)
);

-- A node authenticates by presenting its token; the hash is the lookup key.
CREATE INDEX node_by_token_hash ON node (token_hash);

-- A leasable board. Keyed (org_id, node_id, name) per §6.1: a bare name is only
-- unique within one node of one org, so revision 1's global board id is gone.
CREATE TABLE board (
    org_id     TEXT    NOT NULL REFERENCES org(id),
    node_id    TEXT    NOT NULL REFERENCES node(id),
    name       TEXT    NOT NULL,
    chip       TEXT    NOT NULL,
    tags       TEXT    NOT NULL,               -- newline-joined
    exclusive  INTEGER NOT NULL,               -- 0/1
    state      TEXT    NOT NULL,               -- coarse state label
    first_seen INTEGER NOT NULL,               -- epoch seconds
    last_seen  INTEGER NOT NULL,               -- epoch seconds
    PRIMARY KEY (org_id, node_id, name)
);

-- ---------------------------------------------------------------------------
-- Authorization (tables only; evaluation and minting are separate tasks)
-- ---------------------------------------------------------------------------

-- Sharing: `grant bob --select 'tag=nrf52' --ops flash,attach`. The table exists
-- so the Subject shape it keys off is fixed now; evaluation is a separate task.
-- `subject` holds a rendered SubjectKey ("<org>/<kind>:<id>").
CREATE TABLE grant (
    id       TEXT    NOT NULL PRIMARY KEY,
    org_id   TEXT    NOT NULL REFERENCES org(id),
    subject  TEXT    NOT NULL,
    selector TEXT    NOT NULL,
    ops      TEXT    NOT NULL,                 -- newline-joined AllowedOp labels
    expires  INTEGER                           -- epoch seconds, NULL = no expiry
);

-- Pre-minted, org-scoped, revocable auth keys for unattended node enrollment.
-- Redeemed at `POST /auth/token` for a node token.
CREATE TABLE auth_key (
    key_hash   TEXT    NOT NULL PRIMARY KEY,   -- lowercase hex SHA-256
    org_id     TEXT    NOT NULL REFERENCES org(id),
    tags       TEXT    NOT NULL DEFAULT '',    -- newline-joined
    single_use INTEGER NOT NULL DEFAULT 1,     -- 0/1
    expires    INTEGER,                        -- epoch seconds
    created_by TEXT,
    created_at INTEGER NOT NULL,               -- epoch seconds
    consumed_at INTEGER                        -- epoch seconds, NULL until used
);

-- ---------------------------------------------------------------------------
-- Leases and audit
-- ---------------------------------------------------------------------------

-- Leases granted by the scheduler. `closed_at` is NULL while active. The board
-- is identified by its full (org, node, name) key; `holder` is a rendered
-- SubjectKey.
--
-- Note there is deliberately **no** foreign key onto `board`. Board rows are a
-- best-effort snapshot of what nodes report (a failed `record_board` is warned,
-- not fatal, because the scheduler — not this table — is the source of truth for
-- live lease state). Referencing them would make a transient snapshot failure
-- turn a successful lease grant into a hard error, losing the lease record and
-- the audit trail with it. Tenant scoping does not depend on that FK: it comes
-- from `org_id` plus the `OrgDb` handle, both of which are enforced.
CREATE TABLE leases (
    lease        INTEGER NOT NULL PRIMARY KEY,
    org_id       TEXT    NOT NULL REFERENCES org(id),
    node_id      TEXT    NOT NULL,
    board_name   TEXT    NOT NULL,
    holder       TEXT    NOT NULL,
    granted_at   INTEGER NOT NULL,             -- epoch seconds
    expires      INTEGER NOT NULL,             -- epoch seconds
    closed_at    INTEGER,                      -- epoch seconds, NULL while active
    close_reason TEXT
);

CREATE INDEX idx_leases_open ON leases (org_id, closed_at);

-- Append-only audit log of security-relevant actions.
--
-- `board` holds the **node-local** board name (scoped by org_id + node_id),
-- not a rendered BoardRef, so `ctl logs <board>` filters on the same string the
-- caller typed. `subject` is a rendered SubjectKey.
CREATE TABLE audit_log (
    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,                  -- epoch seconds
    org_id  TEXT    NOT NULL REFERENCES org(id),
    subject TEXT,
    action  TEXT    NOT NULL,
    node_id TEXT,
    board   TEXT,
    lease   INTEGER,
    detail  TEXT
);

CREATE INDEX idx_audit_org_ts ON audit_log (org_id, ts);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- A user's bearer session. Short-lived and refreshable: a session token is a
-- pure bearer credential, so a short TTL is what bounds the value of a leak.
-- Only the lowercase-hex SHA-256 of the token is stored.
--
-- `user_id` carries its foreign key like every other table here. The
-- provisioning order (org → user → member → session) guarantees the row exists,
-- and a session for a nonexistent user is a bug we want to fail loudly at
-- insert rather than discover as an unauthenticated-but-valid token.
CREATE TABLE session (
    token_hash TEXT    NOT NULL PRIMARY KEY,   -- lowercase hex SHA-256
    org_id     TEXT    NOT NULL REFERENCES org(id),
    user_id    TEXT    NOT NULL REFERENCES user(id),
    issued_at  INTEGER NOT NULL,               -- epoch seconds
    expires    INTEGER NOT NULL                -- epoch seconds
);

CREATE INDEX session_by_user ON session (org_id, user_id);

