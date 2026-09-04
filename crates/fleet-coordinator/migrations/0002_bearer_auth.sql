-- Bearer auth (architecture §3.5, §6.2): the private CA is gone.
--
-- Revision 1's mTLS bootstrap tables were struck from `0001_init.sql` rather
-- than created there for this file to drop — that block carried its own "until
-- the bearer-auth task lands they stay" comment, and this is that task. The
-- database is wiped for revision 2 (see 0001's header), so there is no data to
-- migrate and no ALTER-TABLE path is wanted.
--
-- The DROPs below are therefore a **no-op safety net**, not the point of this
-- file: they clean up a development database created between the org-scoping
-- task and this one, where 0001 did still create these tables.

DROP TABLE IF EXISTS enroll_tokens;
DROP TABLE IF EXISTS agent_pins;
