// Bootstrap: resolve the session, render the chrome, dispatch to a page.
//
// Authorization here is **UX only**. Buttons are hidden from the session's
// `role` and from holder identity purely so the UI is not a list of things that
// will 403; every action is enforced server-side and `tests/ui_authz.rs` proves
// that hiding one changes nothing. No page in this tree decides anything.

import * as api from './api.mjs';
import { h, mount, errorBox } from './dom.mjs';
import { route, NAV } from './router.mjs';
import { memberships, orgLabel, userId, role } from './session.mjs';

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

// The acting org lives in the page URL (`/ui/devices?org=<id>`), not in any
// storage: it survives a reload, is shareable, and every client-side
// navigation carries it forward. Absent, the server's default applies (the
// personal org). `api.mjs` appends it to every `/api/v1` call.
function orgFromUrl() {
  const org = new URLSearchParams(window.location.search).get('org');
  return org && org.trim() ? org.trim() : null;
}

/** `path` (no query) with the acting org carried forward. */
function withOrgQuery(path) {
  const org = api.currentOrg();
  return org ? `${path}?org=${encodeURIComponent(org)}` : path;
}

// The live page's own scratch object: which node is being edited, the pending
// registration just inspected, the half-filled grant form, the auth key shown
// once. It survives a `reload()` of the *same* page and is **dropped whole the
// moment the user navigates away**, which is what makes the keys page's
// shown-once panel honest rather than merely worded strongly: there is no
// second reference to the key anywhere, so leaving the page is what deletes it.
//
// One object per mounted page rather than one per `draw()`: a fresh context on
// every render would silently discard everything a page put on it, so an Edit
// button would set a field and then re-render without it.
let mounted = null;
let pageState = {};

/** The context a page's `load()` receives: its own state plus the plumbing. */
function contextFor(page) {
  if (page !== mounted) {
    mounted = page;
    pageState = {};
  }
  pageState.api = api;
  pageState.session = session;
  pageState.navigate = navigate;
  pageState.reload = draw;
  return pageState;
}

/** Re-render the current page. Passed to pages so an action can refresh. */
async function draw() {
  const app = document.getElementById('app');
  if (!session) {
    renderChrome();
    mount(app, await login.load(contextFor('login')));
    return;
  }
  const { page } = route(window.location.pathname);
  renderChrome(page);
  const mod = PAGE_MODULES[page];
  if (!mod) {
    mounted = null;
    pageState = {};
    mount(app, h('section', {}, h('h1', {}, 'Not found'), h('p', { class: 'hint' }, 'No such page.')));
    return;
  }
  const ctx = contextFor(page);
  mount(app, h('p', { class: 'loading' }, 'Loading…'));
  try {
    mount(app, await mod.load(ctx));
  } catch (err) {
    mount(app, errorBox(api.describe(err)));
  }
}

/** The header: nav (when signed in) and who you are. */
function renderChrome(current) {
  const nav = document.getElementById('nav');
  const who = document.getElementById('whoami');
  if (!session) {
    mount(nav, []);
    mount(who, h('span', {}));
    return;
  }
  // Mounted as a list, not wrapped in a single element: `nav` is a flex
  // container and its `gap` only spaces sibling items, so a wrapper would
  // leave one flex item and run the labels together. Do not reintroduce one.
  mount(
    nav,
    NAV.map((entry) =>
      h(
        'a',
        {
          href: withOrgQuery(entry.path),
          class: entry.page === current ? 'active' : '',
          on: { click: (e) => { e.preventDefault(); navigate(entry.path); } },
        },
        entry.label,
      ),
    ),
  );
  const orgs = memberships(session);
  const acting = session.org;
  // The switcher only exists when there is something to switch between. Its
  // options are the server's membership list, rendered as text.
  const orgPart =
    orgs.length > 1
      ? h(
          'select',
          {
            name: 'org',
            title: 'Acting org',
            on: { change: (e) => switchOrg(e.target.value) },
          },
          orgs.map((m) =>
            h('option', { value: m.id, selected: Boolean(acting && acting.id === m.id) }, `${orgLabel(m)} (${m.role})`),
          ),
        )
      : h('span', {}, acting ? orgLabel(acting) : '—');
  mount(
    who,
    h(
      'span',
      {},
      h('span', { class: 'mono' }, session.username || userId(session)),
      ' · ',
      orgPart,
      ' · ',
      h('span', { class: 'role' }, role(session) || 'no role'),
      ' ',
      h('button', { on: { click: signOut } }, 'Sign out'),
    ),
  );
}

/**
 * Act in another org: re-resolve the session there (for the role), keep the
 * choice in the URL, and re-render the current page from scratch — whatever
 * the page held belonged to the previous org.
 */
async function switchOrg(id) {
  api.setOrg(id || null);
  const { pathname } = window.location;
  window.history.pushState({}, '', withOrgQuery(pathname));
  await loadSession();
  mounted = null;
  pageState = {};
  await draw();
}

/** Client-side navigation. */
export function navigate(path) {
  window.history.pushState({}, '', path.includes('?') ? path : withOrgQuery(path));
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
  api.setOrg(null);
  // Everything the last page held, including a minted auth key, goes with it.
  mounted = null;
  pageState = {};
  window.history.pushState({}, '', '/ui/');
  void draw();
}

/** Resolve the session, or leave it null (the login page). */
async function loadSession() {
  try {
    session = await api.get('/api/v1/session', { quiet: true });
  } catch {
    session = null;
    return;
  }
  // `org` is null when the requested org is not one of the user's (a stale
  // link, a revoked membership). Fall back to the default rather than render
  // a UI whose every call will 403.
  if (session && !session.org && api.currentOrg()) {
    api.setOrg(null);
    window.history.replaceState({}, '', window.location.pathname);
    try {
      session = await api.get('/api/v1/session', { quiet: true });
    } catch {
      session = null;
    }
  }
  // Pin the acting org explicitly once known, so every call names it, and
  // make the URL say so too (history `back` then restores the right org).
  if (session && session.org) {
    api.setOrg(session.org.id);
    if (orgFromUrl() !== session.org.id) {
      window.history.replaceState({}, '', withOrgQuery(window.location.pathname));
    }
  }
}

api.setUnauthorizedHandler(() => {
  session = null;
  mounted = null;
  pageState = {};
  void draw();
});

window.addEventListener('popstate', () => {
  void (async () => {
    const org = orgFromUrl();
    if (session && org !== api.currentOrg()) {
      api.setOrg(org);
      await loadSession();
      mounted = null;
      pageState = {};
    }
    await draw();
  })();
});

void (async () => {
  api.setOrg(orgFromUrl());
  await loadSession();
  await draw();
})();
