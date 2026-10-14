// Devices (boards): the inventory `ctl list` renders, plus the two board
// actions phase 4 shipped.
//
// The power-cycle body sends `"<node>/<name>"` — `BoardKeyView.node` is already
// `{org}/{name}`, so the string is `{org}/{node}/{board}`, which
// `BoardRef::answers_to` resolves through its qualified branch. A bare board
// name would be ambiguous across nodes, and "the wrong board was power-cycled"
// is not a failure mode worth saving eight characters for.
//
// Tags: "Edit tags" is shown when the server says `tags_editable` (owner of
// the board's node, or org admin — acting org only). The saved list REPLACES
// the tags the node reports (`boards.toml` / inferred) with a coordinator-held
// override that survives reconnects and is what `tag=` lease selectors match;
// "Reset to node's tags" drops it. The board is addressed through its node
// (`/api/v1/nodes/{node}/boards/{board}`) because a board key contains
// slashes. Tags are rendered as text nodes only, never as HTML.
//
// Buttons are shown from the caller's role and holder identity. That is UX:
// every action is checked server-side, and a hidden button changes nothing
// about what the server will do (tests/ui_authz.rs).

import { h, tags, when, errorBox } from '../dom.mjs';
import { isAdmin, userId } from '../session.mjs';

/** Whether `holder` is the signed-in caller. */
function isSelf(holder, session) {
  return Boolean(holder && holder.kind === 'user' && userId(session) && holder.id === userId(session));
}

/** The node-local node name inside `b.board.node` (`{org}/{name}`). */
export function nodeName(b) {
  const prefix = `${b.board.org}/`;
  return b.board.node.startsWith(prefix) ? b.board.node.slice(prefix.length) : b.board.node;
}

/** The tags cell: the effective tags, marked when they were set in the UI. */
function tagsCell(b) {
  if (!b.tags_overridden) return tags(b.tags);
  const reported = b.reported_tags && b.reported_tags.length ? b.reported_tags.join(', ') : 'none';
  return h(
    'span',
    { title: `Set in the UI; the node reports: ${reported}` },
    tags(b.tags),
    ' ',
    h('span', { class: 'hint' }, '(set in UI)'),
  );
}

/** The inline edit form for one board's tags. */
function editRow(state, b) {
  return h(
    'tr',
    {},
    h(
      'td',
      { colspan: 10 },
      h(
        'form',
        { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onSave(b, e.target); } } },
        h('label', {}, h('span', { class: 'label' }, 'Tags (comma-separated)'),
          h('input', { name: 'tags', value: (b.tags || []).join(', '), autocomplete: 'off' })),
        h(
          'p',
          { class: 'hint' },
          'These replace the tags the node reports (boards.toml). They are kept by the coordinator ' +
            'and are what tag= lease selectors and grants match.',
        ),
        b.tags_overridden
          ? h('p', { class: 'hint' }, `The node reports: ${(b.reported_tags || []).join(', ') || 'no tags'}`)
          : null,
        h(
          'div',
          { class: 'row' },
          h('button', { class: 'primary', type: 'submit' }, 'Save'),
          b.tags_overridden
            ? h('button', { type: 'button', on: { click: () => state.onReset(b) } }, "Reset to node's tags")
            : null,
          h('button', { type: 'button', on: { click: () => state.onEdit(null) } }, 'Cancel'),
        ),
      ),
    ),
  );
}

export function render(state) {
  const { boards, session, error, notice, editing } = state;
  const admin = isAdmin(session);
  const children = [
    h('h1', {}, 'Devices'),
    h('p', { class: 'hint' }, 'Boards this org owns, plus any shared with it by a grant.'),
  ];
  if (error) children.push(errorBox(error));
  if (notice) children.push(h('p', { class: 'warning' }, notice));
  if (!boards || boards.length === 0) {
    children.push(h('p', { class: 'hint' }, 'No boards are visible to you.'));
    return h('section', {}, children);
  }

  const rows = [];
  for (const b of boards) {
    const holder = b.holder;
    const mayRelease = b.lease !== null && b.lease !== undefined && (admin || isSelf(holder, session));
    const actions = [];
    // Power-cycle is refused for a board with no power control at all, which
    // the server would answer as an invalid request; saying so here is UX.
    actions.push(
      h(
        'button',
        {
          disabled: b.power === 'none',
          title: b.power === 'none' ? 'This board has no power control configured.' : 'Cut and restore power',
          on: { click: () => state.onPowerCycle(b) },
        },
        'Power-cycle',
      ),
    );
    if (mayRelease) {
      actions.push(h('button', { class: 'danger', on: { click: () => state.onRelease(b) } }, 'Release'));
    }
    if (b.tags_editable) {
      actions.push(h('button', { on: { click: () => state.onEdit(b.board.key) } }, 'Edit tags'));
    }
    rows.push(h(
      'tr',
      {},
      h('td', { class: 'mono' }, b.board.name),
      h('td', { class: 'mono' }, b.node),
      h('td', {}, b.model || '—'),
      h('td', {}, b.chip),
      h('td', {}, tagsCell(b)),
      h(
        'td',
        { class: 'mono', title: 'Open with: probefleet ctl serial <board> --port <name>' },
        b.serial_ports && b.serial_ports.length ? b.serial_ports.join(', ') : '—',
      ),
      h('td', {}, b.availability),
      h('td', { class: 'mono' }, holder ? holder.key : '—'),
      h('td', {}, b.expires ? when(b.expires) : '—'),
      h('td', { class: 'actions' }, actions),
    ));
    if (editing === b.board.key && b.tags_editable) rows.push(editRow(state, b));
  }

  children.push(
    h(
      'table',
      {},
      h(
        'thead',
        {},
        h(
          'tr',
          {},
          h('th', {}, 'Board'),
          h('th', {}, 'Node'),
          h('th', {}, 'Model'),
          h('th', {}, 'Chip'),
          h('th', {}, 'Tags'),
          h('th', {}, 'Serial'),
          h('th', {}, 'Availability'),
          h('th', {}, 'Holder'),
          h('th', {}, 'Lease expires'),
          h('th', {}, ''),
        ),
      ),
      h('tbody', {}, rows),
    ),
    h(
      'p',
      { class: 'hint' },
      'Leases are taken by a sidecar, not from a browser: a lease held by a tab has nothing to use it.',
    ),
  );
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  const state = {
    boards: [], session, error: ctx.tagError || null, notice: null, editing: ctx.editing || null,
  };
  ctx.tagError = null;
  state.boards = await api.get('/api/v1/boards');

  const tagsPath = (b) =>
    `/api/v1/nodes/${encodeURIComponent(nodeName(b))}/boards/${encodeURIComponent(b.board.name)}`;

  state.onEdit = (key) => {
    ctx.editing = key;
    return ctx.reload();
  };

  state.onSave = async (b, form) => {
    const raw = form.elements.tags.value || '';
    const body = { tags: raw.split(',').map((t) => t.trim()).filter((t) => t.length > 0) };
    try {
      await api.patch(tagsPath(b), body);
      ctx.editing = null;
    } catch (err) {
      ctx.tagError = api.describe(err);
    }
    await ctx.reload();
  };

  state.onReset = async (b) => {
    try {
      await api.del(`${tagsPath(b)}/tags`);
      ctx.editing = null;
    } catch (err) {
      ctx.tagError = api.describe(err);
    }
    await ctx.reload();
  };

  state.onPowerCycle = async (board) => {
    const key = `${board.node}/${board.board.name}`;
    if (!window.confirm(`Power-cycle ${key}? Anything running on it is interrupted.`)) return;
    try {
      await api.post('/api/v1/boards/power-cycle', { board: key });
    } catch (err) {
      window.alert(api.describe(err));
    }
    await ctx.reload();
  };

  state.onRelease = async (board) => {
    const who = board.holder ? board.holder.key : 'its holder';
    if (!window.confirm(`Release lease ${board.lease}? ${who} loses access to the board immediately.`)) return;
    try {
      await api.del(`/api/v1/leases/${board.lease}`);
    } catch (err) {
      window.alert(api.describe(err));
    }
    await ctx.reload();
  };

  return render(state);
}
