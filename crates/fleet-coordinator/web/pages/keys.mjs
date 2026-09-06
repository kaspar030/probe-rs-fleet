// Auth keys: enrollment credentials, minted here and shown exactly once.
//
// This is the one place the browser surface creates a long-lived bearer secret,
// and docs/web-ui.md D4 accepts that cost explicitly. The panel says the key
// will not be shown again, and it means it: the value lives in a local variable
// for the lifetime of this view and is dropped on navigation. It is never put
// into any client-side storage — nothing in this tree touches any storage API
// at all, and `tests/ui_assets.rs` lints for their names.
//
// Every bound comes from `GET /api/v1/grants/limits`: the TTL cap
// (`auth_key_max_ttl_secs`) and the revocation-prefix floor
// (`min_revoke_prefix`). A hardcoded 30 days or 8 characters here would go
// stale silently, which is the whole reason that endpoint exists.

import { h, tags, when, errorBox, find } from '../dom.mjs';

export function render(state) {
  const { keys, limits, minted, error, notice, form } = state;
  const children = [
    h('h1', {}, 'Auth keys'),
    h(
      'p',
      { class: 'hint' },
      'Enrollment credentials. A node key adds a machine that offers probes; a CI key redeems into a ' +
        'workload token bounded by its own tags. Only the SHA-256 of a key is stored, so the key itself ' +
        'exists in exactly one response, once.',
    ),
  ];
  if (error) children.push(errorBox(error));
  if (notice) children.push(h('p', { class: 'warning' }, notice));

  if (minted) {
    children.push(
      h(
        'section',
        { class: 'panel' },
        h('h2', {}, 'Your new key'),
        h('p', { class: 'warning' }, 'Copy it now. This is the only time it will be shown — it is stored nowhere, not even in this page.'),
        h('p', { class: 'secret' }, minted.key),
        h(
          'p',
          { class: 'hint' },
          `hash ${minted.key_hash.slice(0, 16)}… · ${minted.purpose} · ` +
            `${minted.single_use ? 'single use' : 'multi use'} · expires ${when(minted.expires)}`,
        ),
        h('button', { on: { click: state.onDismiss } }, 'Dismiss'),
      ),
    );
  }

  const maxTtlDays = limits ? Math.floor(limits.auth_key_max_ttl_secs / 86400) : null;
  children.push(
    h('h2', {}, 'Mint a key'),
    h(
      'form',
      { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onCreate(); } } },
      h(
        'label',
        {},
        h('span', { class: 'label' }, 'Purpose'),
        h(
          'select',
          { name: 'purpose', on: { change: (e) => state.onField('purpose', e.target.value) } },
          [['node', 'node — enroll a machine'], ['ci', 'ci — redeem into a workload token']].map(([v, label]) =>
            h('option', { value: v, selected: form.purpose === v }, label),
          ),
        ),
      ),
      h(
        'label',
        {},
        h('span', { class: 'label' }, 'Tags (comma-separated)'),
        h('input', {
          name: 'tags',
          value: form.tags,
          autocomplete: 'off',
          on: { input: (e) => state.onField('tags', e.target.value) },
        }),
        h('span', { class: 'hint' }, form.purpose === 'ci' ? 'Required for a CI key: they bound the grant its redemption synthesises.' : 'Stamped onto nodes enrolled with this key.'),
      ),
      h(
        'label',
        {},
        h('span', { class: 'label' }, 'Lifetime (seconds)'),
        h('input', {
          type: 'number',
          name: 'ttl_secs',
          value: form.ttl_secs,
          min: 1,
          max: limits ? limits.auth_key_max_ttl_secs : undefined,
          on: { input: (e) => state.onField('ttl_secs', e.target.value) },
        }),
        h('span', { class: 'hint' }, maxTtlDays === null ? '' : `At most ${maxTtlDays} days; zero is refused.`),
      ),
      h(
        'label',
        {},
        h('input', {
          type: 'checkbox',
          name: 'multi_use',
          checked: form.multi_use,
          on: { change: (e) => state.onField('multi_use', e.target.checked) },
        }),
        ' Multi-use (redeeming does not consume it)',
      ),
      h('button', { class: 'primary', type: 'submit' }, 'Mint key'),
    ),
  );

  children.push(h('h2', {}, 'Existing keys'));
  if (!keys || keys.length === 0) {
    children.push(h('p', { class: 'hint' }, 'No keys.'));
  } else {
    children.push(
      h(
        'table',
        {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'Hash'), h('th', {}, 'Purpose'), h('th', {}, 'Tags'), h('th', {}, 'Use'),
          h('th', {}, 'Expires'), h('th', {}, 'Consumed'), h('th', {}, 'Created by'), h('th', {}, ''))),
        h(
          'tbody',
          {},
          keys.map((k) =>
            h(
              'tr',
              {},
              h('td', { class: 'mono' }, k.key_hash.slice(0, 16)),
              h('td', {}, k.purpose),
              h('td', {}, tags(k.tags)),
              h('td', {}, k.single_use ? 'single' : 'multi'),
              h('td', {}, when(k.expires)),
              h('td', {}, k.consumed_at ? when(k.consumed_at) : '—'),
              h('td', { class: 'mono' }, k.created_by || '—'),
              h('td', { class: 'actions' }, h('button', { class: 'danger', on: { click: () => state.onRevoke(k) } }, 'Revoke')),
            ),
          ),
        ),
      ),
    );
  }
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  ctx.keyForm = ctx.keyForm || { purpose: 'node', tags: '', ttl_secs: 86400, multi_use: false };
  const state = {
    session,
    form: ctx.keyForm,
    // The minted key lives on the navigation context, so it is dropped the
    // moment the user leaves this page. Nothing writes it anywhere else.
    minted: ctx.mintedKey || null,
    notice: ctx.keyNotice || null,
    error: null,
  };
  ctx.keyNotice = null;

  const list = await api.get('/api/v1/auth-keys');
  state.keys = (list && list.keys) || [];
  try {
    state.limits = await api.get('/api/v1/grants/limits');
  } catch {
    state.limits = null;
  }

  state.onField = (field, value) => {
    ctx.keyForm[field] = value;
    if (field === 'purpose' || field === 'multi_use') return ctx.reload();
  };

  state.onDismiss = () => {
    ctx.mintedKey = null;
    return ctx.reload();
  };

  state.onCreate = async () => {
    const form = ctx.keyForm;
    const tagList = String(form.tags || '').split(',').map((t) => t.trim()).filter((t) => t.length > 0);
    const ttl = Number(form.ttl_secs);
    if (!Number.isFinite(ttl) || ttl <= 0) {
      ctx.keyNotice = 'A lifetime of at least one second is required.';
      await ctx.reload();
      return;
    }
    if (state.limits && ttl > state.limits.auth_key_max_ttl_secs) {
      ctx.keyNotice = `The coordinator caps auth-key lifetimes at ${state.limits.auth_key_max_ttl_secs} seconds.`;
      await ctx.reload();
      return;
    }
    if (form.purpose === 'ci' && tagList.length === 0) {
      ctx.keyNotice = 'A CI key needs tags: without them its synthesised grant would cover the whole fleet.';
      await ctx.reload();
      return;
    }
    try {
      ctx.mintedKey = await api.post('/api/v1/auth-keys', {
        tags: tagList,
        ttl_secs: ttl,
        multi_use: Boolean(form.multi_use),
        purpose: form.purpose,
        ops: [],
      });
    } catch (err) {
      ctx.keyNotice = api.describe(err);
    }
    await ctx.reload();
  };

  state.onRevoke = async (key) => {
    const floor = state.limits ? state.limits.min_revoke_prefix : 8;
    const prefix = key.key_hash.slice(0, Math.max(floor, 16));
    const extra = key.purpose === 'ci' ? ' Its CI grant, and any lease held under it, goes too.' : '';
    if (!window.confirm(`Revoke key ${prefix}…?${extra}`)) return;
    try {
      await api.del(`/api/v1/auth-keys/${encodeURIComponent(prefix)}`);
    } catch (err) {
      ctx.keyNotice = api.describe(err);
    }
    await ctx.reload();
  };

  return render(state);
}

/** Test helper: the shown-once panel, or null. */
export function secretPanel(vnode) {
  return find(vnode, (n) => n.tag === 'p' && n.attrs && n.attrs.class === 'secret');
}
