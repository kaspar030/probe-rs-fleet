// Sign in.
//
// Which flow is offered comes from `GET /api/v1/auth/methods`, never from a
// build-time branch — there is no build (docs/web-ui.md D3), and the answer is
// a property of the deployment's config.
//
//   * `authorization_code` — a plain link to `/auth/github/start`. A link and
//     not a fetch: the flow is a browser navigation that ends in a `302 /ui`
//     with cookies attached, and XHR would swallow it.
//   * `device` — the brokered fallback. `POST /api/v1/session/device/start`
//     returns the user code and where to type it (the `device_code` itself
//     stays in an `HttpOnly` cookie), then `.../poll` until `{"status":"ok"}`.
//     Neither route authenticates anything, so neither needs the CSRF header.
//   * `none` — no GitHub config at all; the operator mints a session with
//     `coordinator user-token`.

import { h, errorBox } from '../dom.mjs';

export function render(state) {
  const { method, device, error, polling } = state;
  const children = [h('h1', {}, 'Sign in')];
  if (error) children.push(errorBox(error));

  if (method === 'authorization_code') {
    children.push(
      h('p', {}, 'This coordinator signs in with GitHub.'),
      h('p', {}, h('a', { class: 'button', href: '/auth/github/start' }, 'Continue with GitHub')),
    );
  } else if (method === 'device') {
    if (!device) {
      children.push(
        h('p', {}, 'This coordinator has no OAuth callback registered, so sign-in uses the GitHub device flow.'),
        h('p', {}, h('button', { class: 'primary', on: { click: state.onStart } }, 'Start device sign-in')),
      );
    } else {
      children.push(
        h('p', {}, 'Open GitHub and enter this code:'),
        h('p', { class: 'secret' }, device.user_code),
        h(
          'p',
          {},
          h('a', { href: device.verification_uri, rel: 'noreferrer' }, device.verification_uri),
          ' ',
          h('span', { class: 'hint' }, '(opens github.com)'),
        ),
        h('p', { class: 'hint' }, polling ? 'Waiting for you to approve it on GitHub…' : 'Stopped polling.'),
      );
    }
  } else if (method === 'none') {
    children.push(
      h('p', {}, 'This coordinator has no GitHub configuration, so there is no browser sign-in.'),
      h('p', {}, 'An operator can mint a session on the coordinator host:'),
      h('p', { class: 'mono secret' }, 'probe-rs-fleet coordinator user-token'),
      h('p', { class: 'hint' }, 'That prints a session token for CLI use; the web UI needs a GitHub login.'),
    );
  } else {
    children.push(h('p', { class: 'loading' }, 'Checking which sign-in this deployment offers…'));
  }
  return h('section', {}, children);
}

// The device link is the one absolute URL in this tree. `safeHref` in dom.mjs
// refuses it (only `/…` and `#…` are set as `href`), so it renders as text
// rather than as a link — which is correct: the value comes from GitHub via the
// coordinator, and a UI that turned an upstream string into a live link would
// be one upstream change away from an open redirect.
export async function load(ctx) {
  const { api } = ctx;
  const state = { method: null, device: null, error: null, polling: false, onStart: null };
  try {
    const methods = await api.get('/api/v1/auth/methods', { quiet: true });
    state.method = methods && methods.login;
  } catch (err) {
    state.error = api.describe(err);
    return render(state);
  }

  state.onStart = async () => {
    try {
      const started = await api.post('/api/v1/session/device/start', {}, { quiet: true });
      state.device = started;
      state.polling = true;
      ctx.reload();
      pollUntilSignedIn(ctx, started.interval);
    } catch (err) {
      state.error = api.describe(err);
      ctx.reload();
    }
  };
  return render(state);
}

/** Poll the brokered device flow at the interval GitHub asked for. */
function pollUntilSignedIn(ctx, intervalSecs) {
  const wait = Math.max(1, Number(intervalSecs) || 5) * 1000;
  const tick = async () => {
    try {
      const result = await ctx.api.post('/api/v1/session/device/poll', {}, { quiet: true });
      if (result && result.status === 'ok') {
        // The session arrived as cookies; a reload is the simplest way to pick
        // it up through the same path a fresh visit takes.
        window.location.assign('/ui/');
        return;
      }
    } catch {
      return; // expired or denied: the page shows the code until reloaded.
    }
    window.setTimeout(() => { void tick(); }, wait);
  };
  window.setTimeout(() => { void tick(); }, wait);
}
