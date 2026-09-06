// Agents (nodes): the machines that offer probes.
//
// Editable: tags and adoption policy. **Not the name.** `PATCH
// /api/v1/nodes/{name}` answers `400 invalid_request` to a `name` field, and
// deliberately so: the node id is `{org}/{name}`, `board.node_id` references it
// under enforced foreign keys, `leases.node_id` carries it with no foreign key
// at all, and every live `BoardRef` in the scheduler embeds it. A rename input
// that 400s would be the worst of both answers, so the page says in one line
// what the v1 answer is — delete and re-enroll.
//
// Revoking is a revocation, not a tidy-up, and the confirm says the cascade out
// loud: the node's token dies, its live leases are released, and its
// control-plane connection is closed.

import { h, tags, ago, when, errorBox } from '../dom.mjs';

const ADOPT = ['auto', 'declared'];

function mayEdit(node, session) {
  if (!session) return false;
  if (session.role === 'admin') return true;
  return Boolean(node.owner) && node.owner === session.user;
}

export function render(state) {
  const { nodes, session, editing, error } = state;
  const children = [
    h('h1', {}, 'Agents'),
    h(
      'p',
      { class: 'hint' },
      'Machines enrolled in this org. Renaming is not supported in v1 — a node id is embedded in ' +
        'its boards, its leases and the scheduler; the answer is to revoke the node and re-enroll it.',
    ),
  ];
  if (error) children.push(errorBox(error));
  if (!nodes || nodes.length === 0) {
    children.push(h('p', { class: 'hint' }, 'No machines are enrolled yet.'));
    return h('section', {}, children);
  }

  const rows = [];
  for (const node of nodes) {
    const editable = mayEdit(node, session);
    rows.push(
      h(
        'tr',
        {},
        h('td', { class: 'mono' }, node.name),
        h(
          'td',
          {},
          h('span', { class: `dot ${node.online ? 'online' : 'offline'}` }, node.online ? '●' : '○'),
          ' ',
          node.online ? 'online' : ago(node.last_seen),
        ),
        h('td', {}, tags(node.tags)),
        h('td', {}, node.adopt),
        h('td', { class: 'mono' }, node.owner || '—'),
        h('td', {}, node.boards && node.boards.length ? String(node.boards.length) : '0'),
        h('td', {}, when(node.created_at)),
        h(
          'td',
          { class: 'actions' },
          editable
            ? [
                h('button', { on: { click: () => state.onEdit(node.name) } }, 'Edit'),
                h('button', { class: 'danger', on: { click: () => state.onRevoke(node) } }, 'Revoke'),
              ]
            : h('span', { class: 'hint' }, '—'),
        ),
      ),
    );
    if (editing === node.name) {
      rows.push(
        h(
          'tr',
          {},
          h(
            'td',
            { colspan: 8 },
            h(
              'form',
              { class: 'panel', on: { submit: (e) => { e.preventDefault(); state.onSave(node.name, e.target); } } },
              h('label', {}, h('span', { class: 'label' }, 'Tags (comma-separated)'),
                h('input', { name: 'tags', value: (node.tags || []).join(', '), autocomplete: 'off' })),
              h(
                'label',
                {},
                h('span', { class: 'label' }, 'Adopt policy'),
                h(
                  'select',
                  { name: 'adopt' },
                  ADOPT.map((a) => h('option', { value: a, selected: a === node.adopt }, a)),
                ),
              ),
              h('p', { class: 'hint' }, 'The name cannot be changed; revoke and re-enroll instead.'),
              h(
                'div',
                { class: 'row' },
                h('button', { class: 'primary', type: 'submit' }, 'Save'),
                h('button', { type: 'button', on: { click: () => state.onEdit(null) } }, 'Cancel'),
              ),
            ),
          ),
        ),
      );
    }
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
          h('th', {}, 'Name'),
          h('th', {}, 'Seen'),
          h('th', {}, 'Tags'),
          h('th', {}, 'Adopt'),
          h('th', {}, 'Owner'),
          h('th', {}, 'Boards'),
          h('th', {}, 'Enrolled'),
          h('th', {}, ''),
        ),
      ),
      h('tbody', {}, rows),
    ),
  );
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  const state = { nodes: [], session, editing: ctx.editing || null, error: null };
  state.nodes = await api.get('/api/v1/nodes');

  state.onEdit = (name) => {
    ctx.editing = name;
    void ctx.reload();
  };

  state.onSave = async (name, form) => {
    const raw = form.elements.tags.value || '';
    const body = {
      tags: raw.split(',').map((t) => t.trim()).filter((t) => t.length > 0),
      adopt: form.elements.adopt.value,
    };
    try {
      await api.patch(`/api/v1/nodes/${encodeURIComponent(name)}`, body);
      ctx.editing = null;
    } catch (err) {
      window.alert(api.describe(err));
    }
    await ctx.reload();
  };

  state.onRevoke = async (node) => {
    const message =
      `Revoke ${node.name}?\n\n` +
      'Its node token stops working immediately, any leases it holds are released, ' +
      'its boards leave the inventory and its connection is closed. ' +
      'The machine can only rejoin by enrolling again.';
    if (!window.confirm(message)) return;
    try {
      await api.del(`/api/v1/nodes/${encodeURIComponent(node.name)}`);
    } catch (err) {
      window.alert(api.describe(err));
    }
    await ctx.reload();
  };

  return render(state);
}
