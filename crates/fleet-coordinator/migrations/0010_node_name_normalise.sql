-- Normalise `node.name` to the node-local spelling.
--
-- `OrgDb::ensure_node` (the inventory-report path) used to bind the full
-- org-prefixed node id into `name`, while `Db::register_node_full` (the
-- `share` / `agent up` / auth-key enrollment path) bound the bare name. The
-- same physical machine therefore ended up addressable as `acme/rpi-1` or
-- `rpi-1` depending on which path created its row first — and `name` is the
-- key the browser API addresses nodes by (`OrgDb::node_by_name`,
-- `OrgDb::delete_node`, `OrgDb::list_nodes`'s `ORDER BY name`, and
-- `Db::node_id_in_org_by_name`, whose interactive-approval collision check
-- silently missed a legacy prefixed row and would re-credential an existing
-- machine without the `replaced=` warning). `ensure_node` now writes the bare
-- name; this migration makes existing rows agree.
--
-- `UNIQUE (org_id, name)` was declared on `node` in `0001_init.sql` from the
-- start; this migration is what makes the stored data honour the invariant the
-- schema always claimed.
--
-- Two deliberate details:
--
--   * `substr(...) = org_id || '/'` rather than `LIKE org_id || '/%'`. Org ids
--     are operator-supplied bare TEXT, and `_` / `%` are LIKE metacharacters —
--     a LIKE predicate would match rows this must not touch. `substr` compares
--     literally.
--
--   * The `NOT EXISTS` guard. `UNIQUE (org_id, name)` is live and a failing
--     migration aborts `Db::connect`, i.e. coordinator startup, permanently.
--     A collision is believed impossible (a legacy prefixed row has
--     `id = '{org}/{name}'`, so normalising its name can only collide with a
--     row whose id is that same primary key), but "believed impossible" is not
--     a reason to let a startup path throw. A colliding row keeps its prefixed
--     name — ugly, still addressable — instead of bricking the process.
UPDATE node
   SET name = substr(name, length(org_id) + 2)
 WHERE substr(name, 1, length(org_id) + 1) = org_id || '/'
   AND NOT EXISTS (
       SELECT 1 FROM node AS other
        WHERE other.org_id = node.org_id
          AND other.name   = substr(node.name, length(node.org_id) + 2)
   );
