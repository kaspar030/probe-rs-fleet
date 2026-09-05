-- Grants: give other people access to a subset of your boards (architecture
-- §6.5). `0001_init.sql` created the `grant` table as a shape placeholder,
-- before evaluation existed; this migration makes it usable.
--
-- Two columns and two indexes, and each earns its place:
--
-- * `created_at` — every other credential-shaped row records when it was
--   minted, and `grant list` is unreadable without it.
--
-- * `created_by` — **load-bearing, not decorative.** Revocation follows the
--   rule `POST /auth/keys` established (§6.4): the grant's *creator* may
--   revoke it, and an org admin may revoke any of the org's, including rows
--   with a NULL `created_by` which would otherwise be unrevokable over the
--   API. Without this column the first half of that rule cannot be evaluated.
--
-- * `idx_grant_subject` — the one query in the tree that deliberately reads
--   outside an `OrgDb` (`Db::grants_for_subject`). A grant's whole purpose is
--   to cross an org boundary, so it cannot be scoped by the caller's org; it
--   is scoped by the *subject*, which the caller cannot forge because it comes
--   from the authenticated `Subject`. That lookup runs on every lease request,
--   hence the index.
--
-- * `idx_grant_org` — `grant list`, which is org-scoped as usual.
--
-- Note `expires` stays nullable (a shell-created grant may be perpetual), but
-- the `/client` path refuses to write NULL there: an unbounded grant of
-- somebody else's hardware is exactly the artefact that outlives the reason it
-- was created. That guard lives in Rust, and `state.rs` has a test pinning it.
ALTER TABLE "grant" ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "grant" ADD COLUMN created_by TEXT;

CREATE INDEX idx_grant_subject ON "grant" (subject);
CREATE INDEX idx_grant_org ON "grant" (org_id);
