-- Board tags set from the web UI (task 4565).
--
-- A board's tags normally come from its node's `boards.toml` (or are inferred
-- for an adopted probe) and are written to `board.tags` on every inventory
-- report. An operator can **replace** them from the Devices page; the
-- replacement lives here, in its own table, because `board` rows are upserted
-- on every report and deleted when an adopted probe is unplugged
-- (`OrgDb::prune_boards`). An override must survive both, so an auto-adopted
-- probe that is unplugged and replugged gets its tags back.
--
-- Deliberately **no** foreign key to `board`: the override outlives a pruned
-- row. It does reference the node, and goes with it.
--
-- When a row exists its `tags` *are* the board's effective tag set (what
-- `tag=` lease selectors, grants and `ctl list` see); `board.tags` keeps the
-- tags the node reported.
CREATE TABLE board_tag_override (
    ns_node_id TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    node_id    TEXT    NOT NULL REFERENCES node (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,               -- node-local board name
    tags       TEXT    NOT NULL,               -- newline-joined, `valid_tags`-checked
    updated_by TEXT,                           -- subject key of the editor
    updated_at INTEGER NOT NULL,               -- epoch seconds
    PRIMARY KEY (ns_node_id, node_id, name)
);
