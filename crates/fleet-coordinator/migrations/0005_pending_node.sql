-- Interactive node approval (architecture §4.2 rung 3, §6.4): a headless
-- machine prints a URL and a short code, and a human approves it from a
-- machine where they are logged in.
--
-- ---------------------------------------------------------------------------
-- Why this table is outside `OrgDb`
-- ---------------------------------------------------------------------------
--
-- Every other table a caller can reach carries a NOT NULL `org_id` and is
-- reachable only through `state::OrgDb`, which binds one org into every WHERE
-- clause. This one cannot: **a pending registration has no org yet — deciding
-- which org it joins is precisely what the approval does.** So `org_id` is
-- nullable here, every method on this table lives on `Db` rather than `OrgDb`,
-- and the moment a row is bound (approval) everything downstream goes through
-- `OrgDb` again. This is the same shape as the unauthenticated device flow:
-- pre-tenancy state, not a hole in the tenancy model.
--
-- ---------------------------------------------------------------------------
-- The state machine, in two columns
-- ---------------------------------------------------------------------------
--
--   pending   approved_at IS NULL     AND consumed_at IS NULL
--   approved  approved_at IS NOT NULL AND consumed_at IS NULL
--   denied    approved_at IS NULL     AND consumed_at IS NOT NULL
--   redeemed  approved_at IS NOT NULL AND consumed_at IS NOT NULL
--
-- There is deliberately **no `denied_at` column**: denial is "consumed without
-- ever having been approved", which makes "this code can never be used again"
-- the single predicate `consumed_at IS NOT NULL`. Please do not add one.
--
-- Every transition is a single conditional UPDATE (see `state.rs`), so a
-- double approval cannot bind two orgs and a double redemption cannot mint two
-- node tokens, whatever the concurrency.
--
-- `device_hash` is the lowercase-hex SHA-256 of the enrolling machine's
-- `prfnd1_…` device secret — the secret itself is never stored, exactly as for
-- node tokens, session tokens and auth keys.
--
-- `source_ip` is best effort and **advisory**: behind the expected reverse
-- proxy it is the proxy's address, and NULL when the serve path does not
-- provide one. `X-Forwarded-For` is deliberately not consulted — an
-- unauthenticated header would let the requesting machine choose what the
-- approver sees.
CREATE TABLE pending_node (
    user_code    TEXT    NOT NULL PRIMARY KEY,   -- normalised (Crockford, no hyphen)
    device_hash  TEXT    NOT NULL UNIQUE,        -- hex sha256 of the device secret
    node_name    TEXT    NOT NULL,
    tags         TEXT    NOT NULL DEFAULT '',    -- newline-joined, as elsewhere
    adopt_policy TEXT    NOT NULL,               -- 'auto' | 'declared'
    source_ip    TEXT,                           -- advisory; NULL behind an opaque proxy
    created_at   INTEGER NOT NULL,               -- epoch seconds
    expires      INTEGER NOT NULL,               -- epoch seconds
    org_id       TEXT    REFERENCES org(id),     -- NULL until approved (see above)
    approved_by  TEXT    REFERENCES user(id),    -- NULL until approved
    approved_at  INTEGER,                        -- epoch seconds
    consumed_at  INTEGER                         -- set on redemption OR denial
);

-- The sweep deletes by expiry; the poll route looks up by device hash (already
-- UNIQUE, hence indexed).
CREATE INDEX pending_node_by_expiry ON pending_node (expires);
