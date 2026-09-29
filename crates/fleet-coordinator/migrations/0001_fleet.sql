-- probe-rs-fleet coordinator schema, on forgs (fresh start; the DB was wiped).
--
-- Identity — users, orgs (forgs namespace nodes of kind `org`), memberships,
-- sessions, refresh tokens, API keys, workload tokens, grants, pending
-- device/node approvals and identity audit — lives in forgs' own `forgs_*`
-- tables, created by `forgs_store::migrate` before this migrator runs. What
-- remains here is what only fleet knows about: nodes, boards, leases and the
-- board/node/lease audit trail. Every tenant-owned row carries the forgs
-- namespace id of its org, with a real foreign key into `forgs_ns_node`.
--
-- There is no migration from the pre-forgs schema (0001–0011): the database
-- is wiped on upgrade, by design (task 3892).

CREATE TABLE node (
    id              TEXT    NOT NULL PRIMARY KEY,   -- "<ns id>/<name>" (node_id_for)
    ns_node_id      TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    -- The human whose authority created the node (share / approval); NULL for
    -- an API-key enrollment. A deleted user leaves the node, ownerless.
    owner_user_id   TEXT    REFERENCES forgs_user (id) ON DELETE SET NULL,
    name            TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '',    -- newline-joined
    token_hash      TEXT,                           -- lowercase hex SHA-256 of the node token
    token_issued_at INTEGER,                        -- epoch seconds
    adopt_policy    TEXT    NOT NULL CHECK (adopt_policy IN ('auto', 'declared')),
    last_seen       INTEGER,                        -- epoch seconds
    created_at      INTEGER NOT NULL,               -- epoch seconds
    UNIQUE (ns_node_id, name)
);
CREATE UNIQUE INDEX node_by_token_hash ON node (token_hash) WHERE token_hash IS NOT NULL;

CREATE TABLE board (
    ns_node_id TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    node_id    TEXT    NOT NULL REFERENCES node (id),
    name       TEXT    NOT NULL,
    chip       TEXT    NOT NULL,
    model      TEXT,
    tags       TEXT    NOT NULL,               -- newline-joined
    exclusive  INTEGER NOT NULL,               -- 0/1
    state      TEXT    NOT NULL,               -- coarse, write-only debugging label
    first_seen INTEGER NOT NULL,               -- epoch seconds
    last_seen  INTEGER NOT NULL,               -- epoch seconds
    PRIMARY KEY (ns_node_id, node_id, name)
);

CREATE TABLE leases (
    lease        INTEGER NOT NULL PRIMARY KEY,
    ns_node_id   TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    node_id      TEXT    NOT NULL,
    board_name   TEXT    NOT NULL,
    holder       TEXT    NOT NULL,             -- rendered SubjectKey
    granted_at   INTEGER NOT NULL,             -- epoch seconds
    expires      INTEGER NOT NULL,             -- epoch seconds
    closed_at    INTEGER,                      -- epoch seconds, NULL while active
    close_reason TEXT
);
CREATE INDEX idx_leases_open ON leases (ns_node_id, closed_at);

-- Board / node / lease events. Identity events (logins, mints, key and grant
-- lifecycle, credential rejections) go to `forgs_audit` through forgs'
-- `StoreAuditSink`; the UI's audit page shows both, ordered by time.
--
-- `ns_node_id` stays NOT NULL: every row here is about an org's hardware, and
-- the table is reachable only through `OrgDb`, which binds it.
CREATE TABLE audit_log (
    id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,                  -- epoch seconds
    ns_node_id TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    subject    TEXT,
    action     TEXT    NOT NULL,
    node_id    TEXT,
    board      TEXT,
    lease      INTEGER,
    detail     TEXT
);
CREATE INDEX idx_audit_ns_ts ON audit_log (ns_node_id, ts);
