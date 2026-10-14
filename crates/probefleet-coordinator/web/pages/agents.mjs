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
// Moving (admins only) re-homes the node and every board it hosts in another
// org the user belongs to. The node keeps its token and reconnects by itself;
// grants in this org stop covering its boards, and leased boards refuse the
// move unless "revoke active leases" is ticked. Moving a single board is not
// possible: a board belongs to its machine.
//
// Revoking is a revocation, not a tidy-up, and the confirm says the cascade out
// loud: the node's token dies, its live leases are released, and its
// control-plane connection is closed.
//
// The `Boards` column counts `node.boards`, which is the **declared** set (the
// coordinator's `board` table): every board still in the machine's
// `boards.toml`, whether or not its probe is plugged in right now. Devices
// reads the scheduler instead — the boards that can actually be leased — so
// Agents legitimately shows the larger number when a probe is unplugged. The
// page says so in a hint rather than papering over it by widening
// `GET /api/v1/nodes` with per-board presence.

import { h, tags, ago, when, errorBox } from '../dom.mjs';
import { isAdmin, userId, memberships, orgLabel } from '../session.mjs';

const ADOPT = ['auto', 'declared'];

function mayEdit(node, session) {
  if (!session) return false;
  if (isAdmin(session)) return true;
  return Boolean(node.owner) && node.owner === userId(session);
}

/** The orgs a node in the acting org could be moved to: every other membership. */
export function moveTargets(session) {
  const current = session && session.org ? session.org.id : null;
  return memberships(session).filter((m) => m.id !== current);
}

export function render(state) {
  const { nodes, session, editing, moving, error } = state;
  const children = [
    h('h1', {}, 'Agents'),
    h(
      'p',
      { class: 'hint' },
      'Machines enrolled in this org. Renaming is not supported in v1 — a node id is embedded in ' +
        'its boards, its leases and the scheduler; the answer is to revoke the node and re-enroll it.',
    ),
    h(
      'p',
      { class: 'hint' },
      'Boards counts what each machine declares, including any whose probe is currently unplugged. ' +
        'Devices lists the boards that can be leased right now, so it may show fewer.',
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
    const movable = isAdmin(session) && moveTargets(session).length > 0;
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
                movable
                  ? h('button', { on: { click: () => state.onMoveOpen(node.name) } }, 'Move…')
                  : null,
                h('button', { class: 'danger', on: { click: () => state.onRevoke(node) } }, 'Revoke'),
              ].filter(Boolean)
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
              { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onSave(node.name, e.target); } } },
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
    if (moving === node.name && isAdmin(session)) {
      rows.push(
        h(
          'tr',
          {},
          h(
            'td',
            { colspan: 8 },
            h(
              'form',
              { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onMove(node, e.target); } } },
              h(
                'label',
                {},
                h('span', { class: 'label' }, 'Move to org'),
                h(
                  'select',
                  { name: 'to_org' },
                  moveTargets(session).map((m) =>
                    h('option', { value: m.id }, m.personal ? `${orgLabel(m)} (personal)` : orgLabel(m))),
                ),
              ),
              h('label', {}, h('input', { type: 'checkbox', name: 'force' }), ' Revoke active leases on its boards'),
              h(
                'p',
                { class: 'hint' },
                'All of its boards move with it. Grants in this org stop covering them. ' +
                  'The machine keeps its token and reconnects by itself. You must be a member of the target org.',
              ),
              h(
                'div',
                { class: 'row' },
                h('button', { class: 'primary', type: 'submit' }, 'Move'),
                h('button', { type: 'button', on: { click: () => state.onMoveOpen(null) } }, 'Cancel'),
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
  const state = {
    nodes: [], session, editing: ctx.editing || null, moving: ctx.moving || null, error: null,
  };
  state.nodes = await api.get('/api/v1/nodes');

  state.onEdit = (name) => {
    ctx.editing = name;
    return ctx.reload();
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

  state.onMoveOpen = (name) => {
    ctx.moving = name;
    return ctx.reload();
  };

  state.onMove = async (node, form) => {
    const to = form.elements.to_org.value;
    const force = Boolean(form.elements.force && form.elements.force.checked);
    const target = moveTargets(session).find((m) => m.id === to);
    const message =
      `Move ${node.name} to ${target ? orgLabel(target) : to}?\n\n` +
      'All of its boards move with it and leave this org; grants here stop covering them. ' +
      (force
        ? 'Active leases on its boards are revoked. '
        : 'The move is refused if any of its boards is leased. ') +
      'The machine reconnects by itself with its existing token.';
    if (!window.confirm(message)) return;
    try {
      const out = await api.post(`/api/v1/nodes/${encodeURIComponent(node.name)}/move`, { to_org: to, force });
      ctx.moving = null;
      const lines = [`Moved ${out.node.name} to ${orgLabel(out.to_org)}.`];
      if (out.revoked_leases) lines.push(`${out.revoked_leases} lease(s) revoked.`);
      const who = (g) => g.subject_display || (g.subject && g.subject.key) || '?';
      if (out.grants_lost && out.grants_lost.length) {
        lines.push('', 'Grants here that no longer cover its boards:');
        for (const g of out.grants_lost) lines.push(`  ${who(g)}: ${g.selector}`);
      }
      if (out.grants_gained && out.grants_gained.length) {
        lines.push('', `Grants in ${orgLabel(out.to_org)} that now cover them:`);
        for (const g of out.grants_gained) lines.push(`  ${who(g)}: ${g.selector}`);
      }
      window.alert(lines.join('\n'));
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
