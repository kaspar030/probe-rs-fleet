-- Fleet-issued refresh tokens: the credential that ends the 12-hour login
-- cliff and lets the `probe-rs` sidecar renew its own session.
--
-- ---------------------------------------------------------------------------
-- Why the fleet issues its own token rather than storing GitHub's
-- ---------------------------------------------------------------------------
--
-- Before this table nothing durable survived a login: `http::auth_device_poll`
-- spends the GitHub access token on one `GET /user` call and discards it. So
-- when a 12h session lapsed, the coordinator could not re-establish identity
-- without another device-flow round trip — and the heaviest user of the fleet
-- (a workstation whose only use is `laze` → sidecar → `probe-rs`) was the one
-- credential holder that could not keep itself alive.
--
-- Keeping GitHub's access token was considered and rejected. With the default
-- empty `scope` its blast radius is small, but it can only be revoked **at
-- GitHub**, not by us; it makes the fleet a custodian of somebody else's
-- credentials for no gain; and it would not work at all for a future
-- non-GitHub auth path. A fleet-issued token is revocable by DELETE,
-- auditable, org-scoped, and identical in shape for any future identity
-- provider.
--
-- What it can do is deliberately minimal: minting session tokens for one user
-- in one org, at `POST /auth/token` and nowhere else. It is refused as a
-- connection credential from its `prfr1_` prefix alone, before any database
-- access (`fleet_auth::verify::authenticate`), so no route's `allowed` list
-- can accidentally admit it.
--
-- ---------------------------------------------------------------------------
-- Why redemption does not rotate, and what that costs
-- ---------------------------------------------------------------------------
--
-- OAuth would rotate a refresh token on every use and detect reuse. We do
-- not, and the reason is concurrency. The existing session refresh
-- (`http::refresh_session`) *replaces*: "the old token stops working
-- immediately". That is precisely why the sidecar was never allowed to
-- refresh — two concurrent `probe-rs` invocations would race and one would be
-- left holding a deleted token mid-build.
--
-- A non-rotating refresh token has the same safety property as a `--multi-use`
-- auth key: N concurrent redemptions all succeed and every minted session is
-- independently valid. That property is what makes fixing the sidecar
-- possible at all.
--
-- The cost, stated plainly rather than left to be discovered: **a leaked
-- refresh token is usable for its whole TTL.** It is bounded by
-- `refresh_token_ttl_secs` (30 days by default, the same figure
-- `http::MAX_API_AUTH_KEY_TTL_SECS` already uses for a durable bearer
-- credential a member may hold) and by revocation — `probe-rs-fleet logout
-- --all`, which deletes every session and refresh token of the calling user.
-- This is the same trade a multi-use auth key already makes.
--
-- ---------------------------------------------------------------------------
-- Why it is org-scoped and FK'd, unlike `workload_token`
-- ---------------------------------------------------------------------------
--
-- 0007 explains why a workload token carries no `org_id`: a workload belongs
-- to no tenant. The opposite is true here. A user *is* a member of an org, and
-- a refresh token mints sessions in exactly one of them, so the `session`
-- table's reasoning (0001) applies verbatim: the foreign keys turn a
-- provisioning mistake into a loud failure at insert rather than a valid
-- credential belonging to nobody.
--
-- `issued_at` and `created_at` coincide today. The column is kept anyway,
-- mirroring `session` / `workload_token`, so that a sweep or audit has a
-- creation anchor that stays meaningful if issuance is ever backdated (an
-- imported credential, a migration that re-mints).
CREATE TABLE refresh_token (
    token_hash TEXT    NOT NULL PRIMARY KEY,   -- lowercase hex SHA-256
    org_id     TEXT    NOT NULL REFERENCES org(id),
    user_id    TEXT    NOT NULL REFERENCES user(id),
    issued_at  INTEGER NOT NULL,               -- epoch seconds
    expires    INTEGER NOT NULL,               -- epoch seconds
    created_at INTEGER NOT NULL                -- epoch seconds
);

-- `logout --all` and any future "revoke this user's credentials" path.
CREATE INDEX refresh_token_by_user ON refresh_token (org_id, user_id);
-- The expiry sweep (`sweep::sweep_once`), which is hygiene rather than the
-- security boundary: expiry is enforced at verification time regardless.
CREATE INDEX idx_refresh_token_expires ON refresh_token (expires);
