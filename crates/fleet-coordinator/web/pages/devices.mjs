// Devices (boards): the inventory `ctl list` renders, plus the two board
// actions phase 4 shipped.
//
// The power-cycle body sends `"<node>/<name>"` — `BoardKeyView.node` is already
// `{org}/{name}`, so the string is `{org}/{node}/{board}`, which
// `BoardRef::answers_to` resolves through its qualified branch. A bare board
// name would be ambiguous across nodes, and "the wrong board was power-cycled"
// is not a failure mode worth saving eight characters for.
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

export function render(state) {
  const { boards, session, error, notice } = state;
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

  const rows = boards.map((b) => {
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
    return h(
      'tr',
      {},
      h('td', { class: 'mono' }, b.board.name),
      h('td', { class: 'mono' }, b.node),
      h('td', {}, b.model || '—'),
      h('td', {}, b.chip),
      h('td', {}, tags(b.tags)),
      h('td', {}, b.availability),
      h('td', { class: 'mono' }, holder ? holder.key : '—'),
      h('td', {}, b.expires ? when(b.expires) : '—'),
      h('td', { class: 'actions' }, actions),
    );
  });

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
  const state = { boards: [], session, error: null, notice: null };
  state.boards = await api.get('/api/v1/boards');

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
