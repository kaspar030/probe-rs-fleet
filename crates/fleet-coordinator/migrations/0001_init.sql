-- Coordinator persistent state: boards seen, leases, and the audit log.

-- Every board the coordinator has ever observed (latest snapshot per id).
CREATE TABLE IF NOT EXISTS boards (
    id          TEXT    NOT NULL PRIMARY KEY,
    agent       TEXT    NOT NULL,
    chip        TEXT    NOT NULL,
    tags        TEXT    NOT NULL,          -- newline-joined strings
    exclusive   INTEGER NOT NULL,          -- 0/1
    state       TEXT    NOT NULL,          -- coarse state label
    first_seen  INTEGER NOT NULL,          -- epoch seconds
    last_seen   INTEGER NOT NULL           -- epoch seconds
);

-- Leases granted by the scheduler. `closed_at` is NULL while active.
CREATE TABLE IF NOT EXISTS leases (
    lease       INTEGER NOT NULL PRIMARY KEY,
    board       TEXT    NOT NULL,
    agent       TEXT    NOT NULL,
    holder      TEXT    NOT NULL,
    granted_at  INTEGER NOT NULL,          -- epoch seconds
    expires     INTEGER NOT NULL,          -- epoch seconds
    closed_at   INTEGER,                   -- epoch seconds, NULL while active
    close_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_leases_open ON leases (closed_at);

-- Append-only audit log of security-relevant actions.
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,          -- epoch seconds
    principal   TEXT,
    action      TEXT    NOT NULL,
    board       TEXT,
    lease       INTEGER,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
