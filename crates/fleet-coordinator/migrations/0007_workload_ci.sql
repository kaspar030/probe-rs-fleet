-- CI workload identity: GitHub Actions OIDC exchange, and the auth-key
-- fallback for runners with no workload identity (architecture §6.7).
--
-- ---------------------------------------------------------------------------
-- Why `workload_token` carries no `org_id`
-- ---------------------------------------------------------------------------
--
-- Every table a caller can reach carries a NOT NULL `org_id` and is reachable
-- only through `state::OrgDb`, which binds one org into every WHERE clause.
-- This table deliberately does not, and the reason is not convenience:
--
--   **A workload belongs to no tenant.**
--
-- A workload token proves "a job in repo `owner/name`". That fact is
-- org-independent: several orgs may each grant the same repo access to their
-- hardware, and the repo is a member of none of them. Stamping one org onto
-- the row would either pick an arbitrary winner among the granting orgs or
-- invent a membership that does not exist. So the row records the *credential*
-- and the *claims*, and every authorization decision downstream goes through
-- `grant` — the one query in the tree that is deliberately subject-scoped
-- rather than org-scoped (`Db::grants_for_subject`, see 0006).
--
-- `pending_node` (0005) is the existing precedent for a row that is not
-- org-scoped at rest, and the reasoning is the same shape: pre-tenancy (or,
-- here, extra-tenancy) state, not a hole in the tenancy model. The only query
-- against this table is a lookup by token hash, so there is no cross-tenant
-- read to prevent — the hash IS the capability.
--
-- ---------------------------------------------------------------------------
-- Why `gha` gets a real `org` row
-- ---------------------------------------------------------------------------
--
-- A workload's subject key is `gha/workload:<owner>/<repo>` — `gha` is a
-- reserved *namespace*, not a tenant. It would be tempting to leave it with no
-- `org` row at all, since nothing is scoped to it. That does not survive
-- contact with the code: `core.rs::tear_down_lease` and `extend_lease` both
-- fall back to the **acting subject's** org when the board's org cannot be
-- resolved (a lease being released as its board goes away), and then write an
-- audit row keyed on it. `audit_log.org_id` is `NOT NULL REFERENCES org(id)`,
-- so a row-less namespace turns that rare race into a foreign-key error that
-- propagates out as a coordinator error instead of "no such lease".
--
-- So the namespace gets a real row, of kind `system`. That converts a scattered
-- invariant ("never write an org-scoped row keyed on a workload's namespace")
-- into a structural one, and it costs nothing: no user is ever a member of it,
-- `Db::ensure_org` refuses to let anybody else create or reuse the id, and
-- `CoordinatorConfig::validate` refuses `default_org = "gha"`. Reserving the
-- name in only one of the two creation paths is the trap this avoids.
INSERT INTO org (id, slug, kind, created_at)
VALUES ('gha', 'gha', 'system', unixepoch())
ON CONFLICT(id) DO NOTHING;

-- A minted workload token.
--
-- `repository_owner` is recorded and NEVER authorizing: the per-repo trust rule
-- (§6.7) is precisely that a fork, or a newly created repo under a granted
-- owner, must not inherit hardware access. `git_ref` / `workflow` /
-- `job_workflow_ref` / `run_id` are likewise recorded but not evaluated at v1 —
-- per-ref and per-workflow conditions are a filed follow-up, and capturing the
-- claims now is what makes adding them a pure code change.
CREATE TABLE workload_token (
    token_hash       TEXT    NOT NULL PRIMARY KEY,  -- lowercase hex SHA-256
    subject          TEXT    NOT NULL,              -- rendered SubjectKey
    kind             TEXT    NOT NULL,              -- 'github_oidc' | 'auth_key'
    repository       TEXT,                          -- OIDC only, lowercased
    repository_owner TEXT,                          -- OIDC only; NEVER authorizing
    git_ref          TEXT,
    workflow         TEXT,
    job_workflow_ref TEXT,
    run_id           TEXT,
    issued_at        INTEGER NOT NULL,              -- epoch seconds
    expires          INTEGER NOT NULL               -- epoch seconds
);

-- The expiry sweep's index. Workload tokens are per job and therefore the
-- highest-churn credential in the schema; without this the sweep degrades into
-- a table scan on a table that grows with every CI run.
CREATE INDEX idx_workload_token_expires ON workload_token (expires);

-- ---------------------------------------------------------------------------
-- Auth keys grow a purpose
-- ---------------------------------------------------------------------------
--
-- An auth key has so far minted a **node** token: a machine that *offers*
-- probes. A self-hosted Jenkins box needs the opposite — a client credential
-- that *leases*. Widening what an auth key means would silently turn every
-- existing enrollment key into a board-access credential, so the meaning is
-- made explicit instead and defaults to what every existing row already is.
--
-- `purpose = 'ci'` keys additionally carry `ops`: the operations the grant
-- synthesised at redemption confers. Empty means the redemption path's default.
ALTER TABLE auth_key ADD COLUMN purpose TEXT NOT NULL DEFAULT 'node';
ALTER TABLE auth_key ADD COLUMN ops TEXT NOT NULL DEFAULT '';
