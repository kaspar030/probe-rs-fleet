// Bootstrap: resolve the session, render the chrome, dispatch to a page.
//
// Authorization here is **UX only**. Buttons are hidden from the session's
// `role` and from holder identity purely so the UI is not a list of things that
// will 403; every action is enforced server-side and `tests/ui_authz.rs` proves
// that hiding one changes nothing. No page in this tree decides anything.

import * as api from './api.mjs';
import { h, mount, errorBox } from './dom.mjs';
import { route, NAV } from './router.mjs';

import * as login from './pages/login.mjs';
import * as devices from './pages/devices.mjs';
import * as agents from './pages/agents.mjs';
import * as approve from './pages/approve.mjs';
import * as access from './pages/access.mjs';
import * as keys from './pages/keys.mjs';
import * as audit from './pages/audit.mjs';

const PAGE_MODULES = { devices, agents, approve, access, keys, audit };

// In-memory only. Nothing here is ever persisted: no storage of any kind is
// touched anywhere in this tree (see api.mjs).
let session = null;

/** Re-render the current page. Passed to pages so an action can refresh. */
async function draw() {
  const app = document.getElementById('app');
  if (!session) {
    renderChrome();
    mount(app, await login.load({ api, navigate, reload: draw }));
    return;
  }
  const { page } = route(window.location.pathname);
  renderChrome(page);
  const mod = PAGE_MODULES[page];
  if (!mod) {
    mount(app, h('section', {}, h('h1', {}, 'Not found'), h('p', { class: 'hint' }, 'No such page.')));
    return;
  }
  mount(app, h('p', { class: 'loading' }, 'Loading…'));
  try {
    mount(app, await mod.load({ api, session, navigate, reload: draw }));
  } catch (err) {
    mount(app, errorBox(api.describe(err)));
  }
}

/** The header: nav (when signed in) and who you are. */
function renderChrome(current) {
  const nav = document.getElementById('nav');
  const who = document.getElementById('whoami');
  if (!session) {
    mount(nav, h('span', {}));
    mount(who, h('span', {}));
    return;
  }
  mount(
    nav,
    h(
      'span',
      {},
      NAV.map((entry) =>
        h(
          'a',
          {
            href: entry.path,
            class: entry.page === current ? 'active' : '',
            on: { click: (e) => { e.preventDefault(); navigate(entry.path); } },
          },
          entry.label,
        ),
      ),
    ),
  );
  mount(
    who,
    h(
      'span',
      {},
      h('span', { class: 'mono' }, session.login || session.user),
      ' · ',
      h('span', {}, session.org_slug || session.org),
      ' · ',
      h('span', { class: 'role' }, session.role),
      ' ',
      h('button', { on: { click: signOut } }, 'Sign out'),
    ),
  );
}

/** Client-side navigation. */
export function navigate(path) {
  window.history.pushState({}, '', path);
  void draw();
}

async function signOut() {
  try {
    await api.post('/api/v1/session/logout');
  } catch {
    // A failed logout still drops the in-memory session: the cookie is
    // `HttpOnly`, so the server's answer is the only thing that can clear it,
    // and there is nothing useful to retry from here.
  }
  session = null;
  window.history.pushState({}, '', '/ui/');
  void draw();
}

/** Resolve the session, or leave it null (the login page). */
async function loadSession() {
  try {
    session = await api.get('/api/v1/session', { quiet: true });
  } catch {
    session = null;
  }
}

api.setUnauthorizedHandler(() => {
  session = null;
  void draw();
});

window.addEventListener('popstate', () => { void draw(); });

void (async () => {
  await loadSession();
  await draw();
})();
