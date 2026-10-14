// Approve a pending node registration — the flow behind the URL a headless
// machine prints (`/node/approve`), done properly in the UI so a Pi that
// printed a code can be approved without the CLI.
//
// The warning next to the confirm button is the server's `warning` field,
// rendered **verbatim**. It is `api::APPROVAL_WARNING`, byte-identical to the
// sentence `probefleet node approve` prints, and it ships as a server field
// precisely so a frontend that forgets it shows a visibly empty box rather than
// silently dropping the mitigation. Do not replace it with a copy of the
// string: this page must render the field.
//
// There is no listing of pending registrations, and there is not going to be
// one: a pending registration has no org until an approval binds it, so a listing
// could only show every live code in the deployment — exactly the cross-tenant
// index docs/web-ui.md §4 forbids. Approval is code-driven.
//
// The **target org** is chosen here, before anything is looked up: a session
// is not bound to one org, and approving grants the machine hardware access
// in whichever org the request acts in (`?org=<id>`, sent per call). The
// picker lists the session's memberships and defaults to the org the UI is acting in; the
// inspect call already carries the choice, so the server's `org` field — shown
// in the table and in the confirmation — is the org the approval would bind.
// Changing the org drops a looked-up registration: its collision check and
// `org` answer belonged to the previous choice.

import { h, tags, when, ago, errorBox } from '../dom.mjs';
import { memberships, orgLabel, orgName } from '../session.mjs';

export function render(state) {
  const { pending, error, code, replace, session, targetOrg } = state;
  const orgs = memberships(session);
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
      orgs.length > 0
        ? h('label', {}, h('span', { class: 'label' }, 'Approve into org'),
          h(
            'select',
            { name: 'org', on: { change: (e) => state.onOrg(e.target.value) } },
            orgs.map((m) => h('option', { value: m.id, selected: m.id === targetOrg }, `${orgLabel(m)} (${m.role})`)),
          ))
        : null,
      h('label', {}, h('span', { class: 'label' }, 'Code'),
        h('input', { name: 'code', value: code || '', placeholder: 'ABCD-1234', autocomplete: 'off' })),
      h('button', { class: 'primary', type: 'submit' }, 'Look up'),
    ),
  ];
  if (error) children.push(errorBox(error));
  if (state.notice) children.push(h('p', { class: 'warning' }, state.notice));

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
            h('tr', {}, h('th', {}, 'Joins org'), h('td', { class: 'mono' }, pending.org ? orgName(session, pending.org) : '—')),
            h('tr', {}, h('th', {}, 'State'), h('td', {}, pending.state)),
          ),
        ),
        pending.collides_with
          ? h(
              'p',
              { class: 'warning' },
              `${pending.org ? orgName(session, pending.org) : 'This org'} already has a node called ${pending.node_name} (${pending.collides_with}). ` +
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
          h(
            'button',
            { class: 'primary', on: { click: () => state.onDecide('approve') } },
            pending.org ? `Approve into ${orgName(session, pending.org)}` : 'Approve',
          ),
          h('button', { class: 'danger', on: { click: () => state.onDecide('deny') } }, 'Deny'),
        ),
      ),
    );
  }
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api, session } = ctx;
  const orgs = memberships(session);
  // Default: the org the UI is acting in; else the first membership.
  if (!ctx.targetOrg || !orgs.some((m) => m.id === ctx.targetOrg)) {
    // By id: `api.currentOrg()` is the URL's org *path*, the options are ids.
    const acting = (session && session.org && session.org.id) || null;
    ctx.targetOrg = orgs.some((m) => m.id === acting) ? acting : orgs.length > 0 ? orgs[0].id : acting;
  }
  const state = {
    session,
    targetOrg: ctx.targetOrg,
    pending: ctx.pending || null,
    code: ctx.code || '',
    replace: Boolean(ctx.replace),
    error: ctx.approveError || null,
    notice: ctx.approveNotice || null,
  };
  ctx.approveError = null;
  ctx.approveNotice = null;

  state.onReplace = (on) => {
    ctx.replace = on;
    return ctx.reload();
  };

  state.onOrg = (id) => {
    ctx.targetOrg = id || null;
    ctx.pending = null;
    ctx.replace = false;
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
      ctx.pending = await api.post(
        `/api/v1/nodes/pending/${encodeURIComponent(code)}`,
        { decision: 'inspect' },
        { org: ctx.targetOrg },
      );
    } catch (err) {
      ctx.pending = null;
      ctx.approveError = api.describe(err);
    }
    await ctx.reload();
  };

  state.onDecide = async (decision) => {
    const target = ctx.targetOrg;
    try {
      const decided = await api.post(
        `/api/v1/nodes/pending/${encodeURIComponent(ctx.code)}`,
        { decision, replace: Boolean(ctx.replace) },
        { org: target },
      );
      const into = orgName(session, (decided && decided.org) || target);
      ctx.pending = null;
      ctx.code = '';
      ctx.replace = false;
      ctx.approveError = null;
      ctx.approveNotice =
        decision === 'approve'
          ? `Approved into ${into}. The machine will finish enrolling on its next poll.`
          : 'Denied.';
    } catch (err) {
      ctx.approveError = api.describe(err);
    }
    await ctx.reload();
  };

  return render(state);
}
