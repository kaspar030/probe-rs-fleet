// The audit log tail.
//
// Admin-only, and a 403 says so in words rather than rendering a blank page —
// a member landing here should learn why, not conclude the log is empty.
//
// There is no paging, and the page says so: `logs_core` reads the most recent
// 200 rows and this surface keeps that number rather than inventing a cursor
// API for one consumer. Implying paging exists would be worse than admitting it
// does not.

import { h, when, errorBox } from '../dom.mjs';

export function render(state) {
  const { lines, board, error, denied } = state;
  const children = [h('h1', {}, 'Audit log')];
  if (denied) {
    children.push(
      h('p', { class: 'warning' }, 'Your role cannot read the audit log. It is admin-only in this org.'),
    );
    return h('section', {}, children);
  }
  children.push(
    h(
      'form',
      { class: 'panel', on: { submit: (e) => { e.preventDefault(); state.onFilter(e.target.elements.board.value); } } },
      h('label', {}, h('span', { class: 'label' }, 'Filter by board (node-local name)'),
        h('input', { name: 'board', value: board || '', autocomplete: 'off' })),
      h('div', { class: 'row' },
        h('button', { class: 'primary', type: 'submit' }, 'Filter'),
        board ? h('button', { type: 'button', on: { click: () => state.onFilter('') } }, 'Clear') : null),
    ),
  );
  if (error) children.push(errorBox(error));
  children.push(h('p', { class: 'hint' }, 'The 200 most recent entries, newest first. There is no paging in v1.'));

  if (!lines || lines.length === 0) {
    children.push(h('p', { class: 'hint' }, 'Nothing recorded.'));
    return h('section', {}, children);
  }
  children.push(
    h(
      'table',
      {},
      h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Action'), h('th', {}, 'Board'), h('th', {}, 'Detail'))),
      h(
        'tbody',
        {},
        lines.map((l) =>
          h(
            'tr',
            {},
            h('td', {}, when(l.ts)),
            h('td', { class: 'mono' }, l.action),
            h('td', { class: 'mono' }, l.board || '—'),
            h('td', {}, l.detail || '—'),
          ),
        ),
      ),
    ),
  );
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  const state = { session, board: ctx.auditBoard || '', lines: [], error: null, denied: false };

  state.onFilter = (board) => {
    ctx.auditBoard = String(board || '').trim();
    void ctx.reload();
  };

  const query = state.board ? `?board=${encodeURIComponent(state.board)}` : '';
  try {
    state.lines = await api.get(`/api/v1/audit${query}`);
  } catch (err) {
    if (err && err.status === 403) {
      state.denied = true;
    } else {
      state.error = api.describe(err);
    }
  }
  return render(state);
}
