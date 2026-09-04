-- GitHub identity (architecture §6.4): first login creates the user *and* its
-- personal org.
--
-- `user.github_user_id` already exists (0001); this file adds the uniqueness the
-- device flow depends on. It is a partial index because the interim admin verb
-- (`coordinator user-token`) creates rows with a NULL `github_user_id`, and a
-- plain UNIQUE would collapse them all into one under SQLite's NULL-distinct
-- rules only by accident — being explicit is cheaper than relying on that.
--
-- Why uniqueness matters: `upsert_github_user` resolves an existing user by
-- `github_user_id` and creates one otherwise. Without the index a race between
-- two concurrent first logins for the same human would create two `user` rows
-- and two personal orgs, and the second login would silently land in a
-- different org than the first — the leases and grants would appear to vanish.
CREATE UNIQUE INDEX IF NOT EXISTS user_by_github_id
    ON user (github_user_id) WHERE github_user_id IS NOT NULL;
