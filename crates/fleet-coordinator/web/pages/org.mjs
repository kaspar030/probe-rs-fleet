// Org: who belongs to the org this session acts in, and (for admins) changing
// that. Also where a new org is created, when the deployment allows it.
//
// Membership is listed by any member; adding, re-roling and removing are
// admin-only, and the server enforces that — the controls are hidden from a
// member purely so the page is not a list of things that will 403. The server
// also refuses (`last_admin`) any change that would leave the org with no
// admin, so this page does not try to predict that.
//
// A user can only be added once they exist, i.e. after they have signed in at
// least once; until then the server answers `not_found`, and `describe()` says
// so.
//
// Changing *your own* membership changes the session: demoting yourself
// re-resolves it (your role here is now different), removing yourself means
// you no longer act in this org at all, so the UI falls back to the default.

import { h, errorBox } from '../dom.mjs';
import { isAdmin, orgLabel } from '../session.mjs';

const ROLES = ['member', 'admin'];

function roleSelect(name, value, onChange) {
  return h(
    'select',
    { name, on: onChange ? { change: (e) => onChange(e.target.value) } : {} },
    ROLES.map((r) => h('option', { value: r, selected: value === r }, r)),
  );
}

export function render(state) {
  const { session, members, error, notice } = state;
  const admin = isAdmin(session);
  const acting = session && session.org;
  const children = [
    h('h1', {}, 'Org'),
    h(
      'p',
      { class: 'hint' },
      'Acting in ',
      h('span', { class: 'mono' }, acting ? orgLabel(acting) : '—'),
      ' as ',
      h('span', { class: 'role' }, (acting && acting.role) || 'no role'),
      '.',
    ),
  ];
  if (error) children.push(errorBox(error));
  if (notice) children.push(h('p', { class: 'warning' }, notice));

  children.push(h('h2', {}, 'Members'));
  if (!admin) {
    children.push(h('p', { class: 'hint' }, 'Only admins of this org can change its membership.'));
  }
  if (!members || members.length === 0) {
    children.push(h('p', { class: 'hint' }, 'No members.'));
  } else {
    children.push(
      h(
        'table',
        {},
        h('thead', {}, h('tr', {}, h('th', {}, 'User'), h('th', {}, 'Role'), admin ? h('th', {}, '') : null)),
        h(
          'tbody',
          {},
          members.map((m) =>
            h(
              'tr',
              {},
              h('td', { class: 'mono' }, m.username, session && m.username === session.username ? ' (you)' : ''),
              h('td', {}, admin ? roleSelect('role', m.role, (r) => state.onRole(m, r)) : m.role),
              admin
                ? h('td', { class: 'actions' }, h('button', { class: 'danger', on: { click: () => state.onRemove(m) } }, 'Remove'))
                : null,
            ),
          ),
        ),
      ),
    );
  }

  if (admin) {
    children.push(
      h('h2', {}, 'Add member'),
      h(
        'form',
        { class: 'panel', name: 'add-member', on: { submit: (e) => { e.preventDefault(); return state.onAdd(e.target); } } },
        h(
          'label',
          {},
          h('span', { class: 'label' }, 'Username'),
          h('input', { name: 'username', autocomplete: 'off', required: true }),
          h('span', { class: 'hint' }, 'They must have signed in once before they can be added.'),
        ),
        h('label', {}, h('span', { class: 'label' }, 'Role'), roleSelect('role', 'member', null)),
        h('button', { class: 'primary', type: 'submit' }, 'Add member'),
      ),
    );
  }

  if (session && session.can_create_orgs) {
    children.push(
      h('h2', {}, 'Create an org'),
      h(
        'form',
        { class: 'panel', name: 'create-org', on: { submit: (e) => { e.preventDefault(); return state.onCreateOrg(e.target); } } },
        h(
          'label',
          {},
          h('span', { class: 'label' }, 'Name'),
          h('input', { name: 'name', autocomplete: 'off', required: true }),
          h('span', { class: 'hint' }, 'Lowercase letters, digits and single dashes. You become its admin.'),
        ),
        h('button', { class: 'primary', type: 'submit' }, 'Create org'),
      ),
    );
  }

  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  const state = { session, members: [], notice: ctx.orgNotice || null, error: null };
  ctx.orgNotice = null;

  try {
    state.members = (await api.get('/api/v1/org/members')) || [];
  } catch (err) {
    state.error = api.describe(err);
  }

  const self = (m) => Boolean(session && m.username === session.username);

  // After a successful change to your own membership the session is stale:
  // re-resolve it, in this org if you are still in it, else the default.
  const afterSelfChange = async (removed) => {
    if (typeof ctx.switchOrg === 'function') {
      await ctx.switchOrg(removed ? null : api.currentOrg());
    } else {
      await ctx.reload();
    }
  };

  const setMember = async (username, role) => {
    await api.post('/api/v1/org/members', { username, role });
  };

  state.onRole = async (member, role) => {
    if (role === member.role) return;
    if (self(member) && role !== 'admin' &&
        !window.confirm('Demote yourself? You will no longer be able to manage this org.')) {
      await ctx.reload();
      return;
    }
    try {
      await setMember(member.username, role);
    } catch (err) {
      ctx.orgNotice = api.describe(err);
      await ctx.reload();
      return;
    }
    if (self(member)) await afterSelfChange(false);
    else await ctx.reload();
  };

  state.onRemove = async (member) => {
    const message = self(member)
      ? 'Remove yourself from this org? You will lose access to it immediately.'
      : `Remove ${member.username} from this org?`;
    if (!window.confirm(message)) return;
    try {
      await api.del(`/api/v1/org/members/${encodeURIComponent(member.username)}`);
    } catch (err) {
      ctx.orgNotice = api.describe(err);
      await ctx.reload();
      return;
    }
    if (self(member)) await afterSelfChange(true);
    else await ctx.reload();
  };

  state.onAdd = async (form) => {
    const username = String(form.elements.username.value || '').trim();
    const role = form.elements.role.value || 'member';
    if (!username) {
      ctx.orgNotice = 'Enter a username.';
      await ctx.reload();
      return;
    }
    try {
      await setMember(username, role);
      ctx.orgNotice = `Added ${username} as ${role}.`;
    } catch (err) {
      ctx.orgNotice = api.describe(err);
    }
    await ctx.reload();
  };

  state.onCreateOrg = async (form) => {
    const name = String(form.elements.name.value || '').trim();
    if (!name) {
      ctx.orgNotice = 'Enter a name for the org.';
      await ctx.reload();
      return;
    }
    let created;
    try {
      // Not scoped to the acting org: a new org belongs to the user.
      created = await api.post('/api/v1/orgs', { name }, { org: null });
    } catch (err) {
      ctx.orgNotice = api.describe(err);
      await ctx.reload();
      return;
    }
    if (created && created.id && typeof ctx.switchOrg === 'function') {
      await ctx.switchOrg(created.id);
    } else {
      await ctx.reload();
    }
  };

  return render(state);
}
