// Sign in.
//
// Sign-in is forgs' `/auth/*`, not this UI's. Which providers exist comes from
// `GET /auth/providers` (`{"providers": ["github", …]}`), never from a
// build-time branch — there is no build (docs/web-ui.md D3), and the answer is
// a property of the deployment's config. Each provider is a plain link to
// `/auth/{name}/start?return_to=<this page>`: a link and not a fetch, because
// the flow is a browser navigation that ends in a redirect back to that page
// with cookies attached, and XHR would swallow it. `return_to` is the current
// `/<org>/<page>` when the login page was reached from one (a deep link
// survives sign-in), else `/`, which lands in the personal org. Account creation (signup) is rendered by
// forgs on that same path; this page offers none of its own.
//
// Provider names are server strings, so they go through `dom.mjs` as text and
// are URL-encoded into the href; a name that could not form a same-origin path
// would be dropped by `safeHref` anyway.
//
// With no provider configured there is no browser sign-in; the operator mints
// a session with `coordinator user-token` for CLI use.

import { h, errorBox } from '../dom.mjs';
import { route, pagePath } from '../router.mjs';

/**
 * Where the UI wants to land after a provider's callback: the org page
 * `pathname` names (canonically re-spelled), else `/`.
 */
export function returnTo(pathname) {
  const r = route(pathname === undefined && typeof window !== 'undefined' ? window.location.pathname : pathname);
  return r.org && !r.legacy ? pagePath(r.org, r.page) : '/';
}

/** The start URL for provider `name`, returning to `back` (default `/`). */
export function startHref(name, back = '/') {
  return `/auth/${encodeURIComponent(name)}/start?return_to=${encodeURIComponent(back)}`;
}

/** A provider name, for display. */
function label(name) {
  const s = String(name);
  return s.length === 0 ? s : s[0].toUpperCase() + s.slice(1);
}

export function render(state) {
  const { providers, error } = state;
  const back = state.returnTo || '/';
  const children = [h('h1', {}, 'Sign in')];
  if (error) children.push(errorBox(error));

  if (providers === null || providers === undefined) {
    if (!error) children.push(h('p', { class: 'loading' }, 'Checking which sign-in this deployment offers…'));
  } else if (providers.length === 0) {
    children.push(
      h('p', {}, 'This coordinator has no login provider configured, so there is no browser sign-in.'),
      h('p', {}, 'An operator can mint a session on the coordinator host:'),
      h('p', { class: 'mono secret' }, 'probefleet coordinator user-token'),
      h('p', { class: 'hint' }, 'That prints a session token for CLI use; the web UI needs a login provider.'),
    );
  } else {
    children.push(
      h('p', {}, providers.length === 1 ? 'Continue with:' : 'Choose how to sign in:'),
      h(
        'div',
        { class: 'row' },
        providers.map((name) => h('a', { class: 'button', href: startHref(name, back) }, `Continue with ${label(name)}`)),
      ),
    );
  }
  return h('section', {}, children);
}

export async function load(ctx) {
  const { api } = ctx;
  const state = { providers: null, error: null, returnTo: returnTo() };
  try {
    const body = await api.get('/auth/providers', { quiet: true });
    const list = body && Array.isArray(body.providers) ? body.providers : [];
    state.providers = list.filter((p) => typeof p === 'string' && p.length > 0);
  } catch (err) {
    state.error = api.describe(err);
  }
  return render(state);
}
