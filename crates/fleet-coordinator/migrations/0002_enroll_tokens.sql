-- Bootstrap-enrollment state: one-time secrets and DB-backed agent pins.

-- One-time bootstrap secrets minted by `coordinator enroll`. The secret itself
-- is never stored; only its lowercase-hex SHA-256. `consumed_at` is NULL until
-- the secret is used (single-use), and `expires_at` enforces the TTL.
CREATE TABLE IF NOT EXISTS enroll_tokens (
    secret_hash TEXT    NOT NULL PRIMARY KEY, -- lowercase hex SHA-256 of the secret
    principal   TEXT    NOT NULL,             -- cert CN to issue (and, for agents, the agent id)
    kind        TEXT    NOT NULL,             -- 'agent' | 'client'
    created_at  INTEGER NOT NULL,             -- epoch seconds
    expires_at  INTEGER NOT NULL,             -- epoch seconds
    consumed_at INTEGER                       -- epoch seconds, NULL until consumed
);

-- Agent pins recorded automatically on successful enrollment, so the manual
-- `[pinned_agents]` edit disappears. Maps an issued client-cert fingerprint to
-- the agent id it is allowed to claim.
CREATE TABLE IF NOT EXISTS agent_pins (
    fingerprint TEXT    NOT NULL PRIMARY KEY, -- lowercase hex SHA-256 of the cert DER
    agent_id    TEXT    NOT NULL,
    created_at  INTEGER NOT NULL              -- epoch seconds
);
