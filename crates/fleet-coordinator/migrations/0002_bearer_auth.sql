-- Bearer auth (architecture §3.5, §6.2): the private CA is gone.
--
-- Revision 1's mTLS bootstrap tables (`enroll_tokens`, `agent_pins`) were struck
-- from `0001_init.sql` rather than created there for this file to drop. That
-- block carried its own "until the bearer-auth task lands they stay" comment,
-- and this is that task. The `session` table and the node token columns landed
-- in `0001` for the same reason: the database is wiped for revision 2 (see
-- 0001's header), so there is no data to migrate and no ALTER-TABLE path is
-- wanted.
--
-- Which leaves this file with nothing to do. It exists because editing `0001`
-- changes its checksum, and sqlx validates recorded checksums on connect: any
-- database carrying the old `0001` is rejected before it reaches this file, so
-- the DROPs below can never actually run against one. They are kept as a
-- belt-and-braces no-op rather than deleted, and the file itself keeps the
-- migration sequence monotonic for the next task that needs to add one.
--
-- If you have a pre-revision-2 development database, delete it; that is the
-- documented upgrade path.

DROP TABLE IF EXISTS enroll_tokens;
DROP TABLE IF EXISTS agent_pins;
