// Access: the grants this org has issued outward.
//
// This is the page that has to be honest, because the op set is not what it
// looks like. `GET /api/v1/grants/limits` returns, per op, where it is actually
// enforced (`agent` / `coordinator` / `nobody`) and whether it implies
// `attach`; the checkboxes are built from that response and **never** from a
// hardcoded list, so the picker cannot drift from `AllowedOp` the first time an
// op moves. `flash` / `erase` / `reset` are recorded intent and audit, not
// enforcement: they travel inside a relayed data channel nobody parses. A
// picker that rendered all six identically would read as a permission system
// this is not.
//
// The selector is built as the **canonical string a CLI would send** — the raw
// field always shows exactly what will be transmitted — because a grant's
// meaning must not depend on which surface wrote it. The server canonicalises;
// this page does not invent a structured form.
//
// Expiry is mandatory and bounded from `limits`, using the **server's** `now`
// rather than the browser's. That difference is exactly what turns "one minute
// from now" into a 400.

import { h, when, errorBox, findAll } from '../dom.mjs';

const TERM_KINDS = ['board', 'chip', 'tag'];

/** Join selector rows into the canonical `a && b` string. */
export function selectorString(rows) {
  return rows
    .filter((r) => r && r.value && String(r.value).trim().length > 0)
    .map((r) => `${r.kind}=${String(r.value).trim()}`)
    .join(' && ');
}

/** Human copy for an op's enforcement reality. */
export function enforcementNote(op) {
  switch (op.enforced_by) {
    case 'agent':
      return 'enforced by the agent';
    case 'coordinator':
      return 'enforced by the coordinator';
    default:
      return 'not enforced anywhere — recorded intent and audit only';
  }
}

export function render(state) {
  const { grants, limits, session, error, notice, form } = state;
  const admin = session && session.role === 'admin';
  const children = [
    h('h1', {}, 'Access'),
    h('p', { class: 'hint' }, 'Grants this org has issued: hardware here, shared with a subject who is not in it.'),
  ];
  if (error) children.push(errorBox(error));
  if (notice) children.push(h('p', { class: 'warning' }, notice));

  // -- listing ------------------------------------------------------------
  if (!grants || grants.length === 0) {
    children.push(h('p', { class: 'hint' }, 'No grants issued.'));
  } else {
    children.push(
      h(
        'table',
        {},
        h(
          'thead',
          {},
          h('tr', {},
            h('th', {}, 'Id'), h('th', {}, 'Grantee'), h('th', {}, 'Selector'),
            h('th', {}, 'Ops'), h('th', {}, 'Expires'), h('th', {}, 'Created by'), h('th', {}, '')),
        ),
        h(
          'tbody',
          {},
          grants.map((g) => {
            const mine = session && g.created_by && g.created_by === session.user;
            return h(
              'tr',
              {},
              h('td', { class: 'mono' }, g.id.slice(0, 12)),
              h('td', { class: 'mono' }, g.subject.key),
              h('td', { class: 'mono' }, g.selector),
              h('td', {}, (g.ops || []).join(', ')),
              h('td', {}, g.expires ? when(g.expires) : '—'),
              h('td', { class: 'mono' }, g.created_by || '—'),
              h(
                'td',
                { class: 'actions' },
                admin || mine
                  ? h('button', { class: 'danger', on: { click: () => state.onRevoke(g) } }, 'Revoke')
                  : h('span', { class: 'hint' }, '—'),
              ),
            );
          }),
        ),
      ),
    );
  }

  // -- create -------------------------------------------------------------
  if (!admin) {
    children.push(
      h('p', { class: 'hint' }, 'Creating a grant is admin-only: a grant points outward, at somebody who is not in this org.'),
    );
    return h('section', {}, children);
  }
  if (!limits) {
    children.push(h('p', { class: 'loading' }, 'Loading the grant limits…'));
    return h('section', {}, children);
  }

  const maxExpiry = limits.now + limits.max_ttl_secs;
  children.push(
    h('h2', {}, 'Create a grant'),
    h(
      'form',
      { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onCreate(); } } },
      h(
        'label',
        {},
        h('span', { class: 'label' }, 'Grantee'),
        h(
          'div',
          { class: 'row' },
          h(
            'select',
            { name: 'grantee_kind', on: { change: (e) => state.onField('granteeKind', e.target.value) } },
            [
              ['login', 'GitHub login'],
              ['id', 'GitHub id (gh-<id>)'],
              ['subject', 'Subject key'],
              ['repo', 'CI repository (owner/name)'],
            ].map(([v, label]) => h('option', { value: v, selected: form.granteeKind === v }, label)),
          ),
          h('input', {
            name: 'grantee',
            value: form.grantee,
            autocomplete: 'off',
            placeholder: form.granteeKind === 'repo' ? 'owner/name' : '',
            on: { input: (e) => state.onField('grantee', e.target.value) },
          }),
        ),
        h(
          'span',
          { class: 'hint' },
          form.granteeKind === 'repo'
            ? 'Sent as repo:owner/name — a bare owner/name resolves to nothing.'
            : 'Resolved now, to an immutable user id, so a later rename cannot take the grant over.',
        ),
      ),

      h('span', { class: 'label' }, 'Selector'),
      h(
        'div',
        {},
        form.selector.map((row, index) =>
          h(
            'div',
            { class: 'row' },
            h(
              'select',
              { on: { change: (e) => state.onSelectorKind(index, e.target.value) } },
              TERM_KINDS.map((k) => h('option', { value: k, selected: row.kind === k }, k)),
            ),
            h('input', {
              value: row.value,
              autocomplete: 'off',
              on: {
                input: (e) => state.onSelectorValue(index, e.target.value),
                // `change` fires on blur/enter, not per keystroke: refreshing
                // the preview on `input` would take focus out of the field the
                // user is still typing in.
                change: () => state.onSelectorCommit(),
              },
            }),
            h('button', { type: 'button', on: { click: () => state.onRemoveTerm(index) } }, 'Remove'),
          ),
        ),
      ),
      h('button', { type: 'button', on: { click: state.onAddTerm } }, 'Add term'),
      h(
        'p',
        { class: 'hint' },
        'Terms are joined with && and sent as the canonical string a CLI would send. ',
        'An empty selector is refused: an empty tag set matches every board.',
      ),
      h('p', { class: 'mono secret' }, selectorString(form.selector) || '(empty)'),

      h('span', { class: 'label' }, 'Operations'),
      h(
        'div',
        {},
        limits.ops.map((op) =>
          h(
            'label',
            {},
            h('input', {
              type: 'checkbox',
              name: `op_${op.op}`,
              checked: form.ops.includes(op.op),
              on: { change: (e) => state.onOp(op, e.target.checked) },
            }),
            ' ',
            h('span', { class: 'mono' }, op.op),
            ' ',
            h('span', { class: `enforced ${op.enforced_by === 'nobody' ? 'nobody' : ''}` }, enforcementNote(op)),
            op.implies_attach ? h('span', { class: 'hint' }, ' · implies attach') : null,
          ),
        ),
      ),
      h(
        'p',
        { class: 'hint' },
        'Ops marked "not enforced anywhere" are flash, erase and reset: they travel inside a relayed ' +
          'data channel the fleet never parses, so recording them is intent and audit, never a control. ' +
          'Any data-plane op implies attach, and the server adds it.',
      ),

      h(
        'label',
        {},
        h('span', { class: 'label' }, 'Expires (required)'),
        h('input', {
          type: 'datetime-local',
          name: 'expires',
          value: form.expires,
          min: localInput(limits.now + 60),
          max: localInput(maxExpiry),
          on: { input: (e) => state.onField('expires', e.target.value) },
        }),
        h(
          'span',
          { class: 'hint' },
          `Must be in the future and at most ${Math.floor(limits.max_ttl_secs / 86400)} days away ` +
            `(the coordinator's clock says ${when(limits.now)}).`,
        ),
      ),
      h('button', { class: 'primary', type: 'submit' }, 'Create grant'),
    ),
  );
  return h('section', {}, children);
}

/** Epoch seconds -> the `datetime-local` spelling, in the browser's zone. */
export function localInput(secs) {
  const d = new Date(Number(secs) * 1000);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** The `subject` field to send, from the picker's mode and value. */
export function granteeString(kind, value) {
  const v = String(value || '').trim();
  return kind === 'repo' ? `repo:${v}` : v;
}

export async function load(ctx) {
  const { api, session } = ctx;
  ctx.grantForm = ctx.grantForm || {
    granteeKind: 'login',
    grantee: '',
    selector: [{ kind: 'tag', value: '' }],
    ops: ['attach'],
    expires: '',
  };
  const state = { session, error: null, notice: ctx.grantNotice || null, form: ctx.grantForm };
  ctx.grantNotice = null;

  state.grants = await api.get('/api/v1/grants');
  try {
    state.limits = await api.get('/api/v1/grants/limits');
  } catch {
    state.limits = null;
  }

  state.onField = (field, value) => {
    ctx.grantForm[field] = value;
    if (field === 'granteeKind') return ctx.reload();
  };
  state.onSelectorKind = (index, kind) => {
    ctx.grantForm.selector[index].kind = kind;
    return ctx.reload();
  };
  state.onSelectorValue = (index, value) => { ctx.grantForm.selector[index].value = value; };
  /** Refresh the "exactly what will be sent" preview once a term is finished. */
  state.onSelectorCommit = () => ctx.reload();
  state.onAddTerm = () => {
    ctx.grantForm.selector.push({ kind: 'tag', value: '' });
    return ctx.reload();
  };
  state.onRemoveTerm = (index) => {
    ctx.grantForm.selector.splice(index, 1);
    if (ctx.grantForm.selector.length === 0) ctx.grantForm.selector.push({ kind: 'tag', value: '' });
    return ctx.reload();
  };
  state.onOp = (op, on) => {
    const set = new Set(ctx.grantForm.ops);
    if (on) {
      set.add(op.op);
      // Shown, not silently applied: the server adds `attach` for a data-plane
      // op, and the CLI shows the implication too.
      if (op.implies_attach) set.add('attach');
    } else {
      set.delete(op.op);
    }
    ctx.grantForm.ops = [...set];
    return ctx.reload();
  };

  state.onCreate = async () => {
    const form = ctx.grantForm;
    const selector = selectorString(form.selector);
    if (!selector) {
      ctx.grantNotice = 'A selector is required: an empty expression would match every board in the org.';
      await ctx.reload();
      return;
    }
    if (!form.expires) {
      ctx.grantNotice = 'An expiry is required.';
      await ctx.reload();
      return;
    }
    const expires = Math.floor(new Date(form.expires).getTime() / 1000);
    if (!Number.isFinite(expires) || expires <= state.limits.now) {
      ctx.grantNotice = "The expiry must be in the future by the coordinator's clock.";
      await ctx.reload();
      return;
    }
    if (form.ops.length === 0) {
      ctx.grantNotice = 'Pick at least one operation.';
      await ctx.reload();
      return;
    }
    try {
      await api.post('/api/v1/grants', {
        subject: granteeString(form.granteeKind, form.grantee),
        selector,
        ops: form.ops,
        expires,
      });
      ctx.grantForm = null;
      ctx.grantNotice = `Granted ${selector} to ${granteeString(form.granteeKind, form.grantee)}.`;
    } catch (err) {
      ctx.grantNotice = api.describe(err);
    }
    await ctx.reload();
  };

  state.onRevoke = async (grant) => {
    const message =
      `Revoke grant ${grant.id.slice(0, 12)}?\n\n` +
      `${grant.subject.key} loses access to ${grant.selector} immediately, and any lease they hold ` +
      'on a board they may no longer use is released.';
    if (!window.confirm(message)) return;
    try {
      await api.del(`/api/v1/grants/${encodeURIComponent(grant.id)}`);
    } catch (err) {
      ctx.grantNotice = api.describe(err);
    }
    await ctx.reload();
  };

  return render(state);
}

/** Test helper: every checkbox name in a rendered tree. */
export function checkboxNames(vnode) {
  return findAll(vnode, (n) => n.tag === 'input' && n.attrs && n.attrs.type === 'checkbox')
    .map((n) => n.attrs.name);
}
