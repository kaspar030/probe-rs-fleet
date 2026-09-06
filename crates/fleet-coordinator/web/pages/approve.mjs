// Approve a pending node registration — the flow behind the URL a headless
// machine prints (`/node/approve`), done properly in the UI so a Pi that
// printed a code can be approved without the CLI.
//
// The warning next to the confirm button is the server's `warning` field,
// rendered **verbatim**. It is `api::APPROVAL_WARNING`, byte-identical to the
// sentence `probe-rs-fleet node approve` prints, and it ships as a server field
// precisely so a frontend that forgets it shows a visibly empty box rather than
// silently dropping the mitigation. Do not replace it with a copy of the
// string: this page must render the field.
//
// There is no listing of pending registrations, and there is not going to be
// one: `pending_node.org_id` is NULL until an approval binds it, so a listing
// could only show every live code in the deployment — exactly the cross-tenant
// index docs/web-ui.md §4 forbids. Approval is code-driven.

import { h, tags, when, ago, errorBox } from '../dom.mjs';

export function render(state) {
  const { pending, error, code, replace } = state;
  const children = [
    h('h1', {}, 'Approve a machine'),
    h(
      'p',
      { class: 'hint' },
      'A machine with no credential printed a short code on its own terminal. Type it here to see ' +
        'what it is asking for, then approve or deny.',
    ),
    h(
      'form',
      { class: 'panel', on: { submit: (e) => { e.preventDefault(); return state.onInspect(e.target.elements.code.value); } } },
      h('label', {}, h('span', { class: 'label' }, 'Code'),
        h('input', { name: 'code', value: code || '', placeholder: 'ABCD-1234', autocomplete: 'off' })),
      h('button', { class: 'primary', type: 'submit' }, 'Look up'),
    ),
  ];
  if (error) children.push(errorBox(error));

  if (pending) {
    children.push(
      h(
        'section',
        { class: 'panel' },
        h('h2', {}, 'Pending registration'),
        h(
          'table',
          {},
          h('tbody', {},
            h('tr', {}, h('th', {}, 'Code'), h('td', { class: 'mono' }, pending.user_code)),
            h('tr', {}, h('th', {}, 'Requested name'), h('td', { class: 'mono' }, pending.node_name)),
            h('tr', {}, h('th', {}, 'Requested tags'), h('td', {}, tags(pending.tags))),
            h('tr', {}, h('th', {}, 'Adopt policy'), h('td', {}, pending.adopt)),
            h('tr', {}, h('th', {}, 'Source address'), h('td', { class: 'mono' }, pending.source_ip || 'unknown')),
            h('tr', {}, h('th', {}, 'Started'), h('td', {}, `${when(pending.created_at)} (${ago(pending.created_at)})`)),
            h('tr', {}, h('th', {}, 'Expires'), h('td', {}, when(pending.expires))),
            h('tr', {}, h('th', {}, 'Joins org'), h('td', { class: 'mono' }, pending.org || '—')),
            h('tr', {}, h('th', {}, 'State'), h('td', {}, pending.state)),
          ),
        ),
        pending.collides_with
          ? h(
              'p',
              { class: 'warning' },
              `Your org already has a node called ${pending.node_name} (${pending.collides_with}). ` +
                'Approving with "replace" re-credentials that node — the machine currently using it stops working.',
            )
          : null,
        // The server's sentence, verbatim. Not this file's to reword.
        h('p', { class: 'warning' }, pending.warning || ''),
        h(
          'label',
          {},
          h('input', {
            type: 'checkbox',
            name: 'replace',
            checked: Boolean(replace),
            on: { change: (e) => state.onReplace(e.target.checked) },
          }),
          ' Replace an existing node of the same name (re-credential it)',
        ),
        h(
          'div',
          { class: 'row' },
          h('button', { class: 'primary', on: { click: () => state.onDecide('approve') } }, 'Approve'),
          h('button', { class: 'danger', on: { click: () => state.onDecide('deny') } }, 'Deny'),
        ),
      ),
    );
  }
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api } = ctx;
  const state = {
    pending: ctx.pending || null,
    code: ctx.code || '',
    replace: Boolean(ctx.replace),
    error: ctx.approveError || null,
  };
  ctx.approveError = null;

  state.onReplace = (on) => {
    ctx.replace = on;
    return ctx.reload();
  };

  state.onInspect = async (raw) => {
    const code = String(raw || '').trim();
    ctx.code = code;
    if (!code) {
      ctx.approveError = 'Enter the code the machine printed.';
      ctx.pending = null;
      await ctx.reload();
      return;
    }
    try {
      // Any spelling `user_code::normalise` accepts is fine; the server
      // normalises, so this page does not reimplement the grammar.
      ctx.pending = await api.post(`/api/v1/nodes/pending/${encodeURIComponent(code)}`, { decision: 'inspect' });
    } catch (err) {
      ctx.pending = null;
      ctx.approveError = api.describe(err);
    }
    await ctx.reload();
  };

  state.onDecide = async (decision) => {
    try {
      await api.post(`/api/v1/nodes/pending/${encodeURIComponent(ctx.code)}`, {
        decision,
        replace: Boolean(ctx.replace),
      });
      ctx.pending = null;
      ctx.code = '';
      ctx.replace = false;
      ctx.approveError = null;
      window.alert(decision === 'approve' ? 'Approved. The machine will finish enrolling on its next poll.' : 'Denied.');
    } catch (err) {
      ctx.approveError = api.describe(err);
    }
    await ctx.reload();
  };

  return render(state);
}
