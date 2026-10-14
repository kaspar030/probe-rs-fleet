// Bootstrap: resolve the session, render the chrome, dispatch to a page.
//
// Authorization here is **UX only**. Buttons are hidden from the session's
// `role` and from holder identity purely so the UI is not a list of things that
// will 403; every action is enforced server-side and `tests/ui_authz.rs` proves
// that hiding one changes nothing. No page in this tree decides anything.

import * as api from './api.mjs';
import { h, mount, errorBox } from './dom.mjs';
import { route, NAV, PAGES, pagePath } from './router.mjs';
import { memberships, orgLabel, orgPath, personalOrg, userId, role } from './session.mjs';

import * as login from './pages/login.mjs';
import * as devices from './pages/devices.mjs';
import * as agents from './pages/agents.mjs';
import * as approve from './pages/approve.mjs';
import * as access from './pages/access.mjs';
import * as keys from './pages/keys.mjs';
import * as orgPage from './pages/org.mjs';
import * as audit from './pages/audit.mjs';

const PAGE_MODULES = { devices, agents, approve, access, keys, org: orgPage, audit };

// In-memory only. Nothing here is ever persisted: no storage of any kind is
// touched anywhere in this tree (see api.mjs).
let session = null;

// The acting org lives in the page *path* (`/<org>/devices`), not in any
// storage or query string: it survives a reload, is shareable, and every
// client-side navigation carries it forward. `api.mjs` sends it to every
// `/api/v1` call as `?org=<path>`; the server resolves a path or an id and
// re-checks membership every time.
//
// `noAccess` is set when the URL names an org the session cannot act in —
// nonexistent, not a member, or renamed away. Those cases are deliberately
// one page with one sentence: the API cannot tell them apart either.
let noAccess = false;

/** The page a URL shows, as a real page name (landing and not-found → devices). */
function pageOf(r) {
  return PAGES.includes(r.page) ? r.page : 'devices';
}

/** The acting org's URL segment, or null before a session resolves one. */
function actingPath() {
  return session && session.org ? orgPath(session.org) : null;
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
  pageState.switchOrg = switchOrg;
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
  if (noAccess) {
    mounted = null;
    pageState = {};
    const home = personalOrg(session);
    mount(
      app,
      h(
        'section',
        {},
        h('h1', {}, 'No access'),
        h('p', {}, 'No such org, or you are not a member.'),
        home
          ? h('p', {}, h('a', {
              href: pagePath(orgPath(home), 'devices'),
              on: { click: (e) => { e.preventDefault(); void switchOrg(orgPath(home)); } },
            }, 'Go to your personal org'))
          : null,
      ),
    );
    return;
  }
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
  // The org the links point into: the acting one, else the one the URL names
  // (so the nav of the no-access page still reads as that org's).
  const linkOrg = actingPath() || route(window.location.pathname).org;
  mount(
    nav,
    (linkOrg ? NAV : []).map((entry) =>
      h(
        'a',
        {
          href: pagePath(linkOrg, entry.page),
          class: entry.page === current ? 'active' : '',
          on: { click: (e) => { e.preventDefault(); navigate(entry.page); } },
        },
        entry.label,
      ),
    ),
  );
  const orgs = memberships(session);
  const acting = session.org;
  // The switcher only exists when there is something to switch between. Its
  // options are the server's membership list, rendered as text; their values
  // are org paths, since switching navigates to `/<org>/<same page>`.
  const orgPart =
    orgs.length > 1 || (!acting && orgs.length > 0)
      ? h(
          'select',
          {
            name: 'org',
            title: 'Acting org',
            on: { change: (e) => switchOrg(e.target.value) },
          },
          [
            acting ? null : h('option', { value: '', selected: true, disabled: true }, '— choose an org —'),
            ...orgs.map((m) =>
              h('option', { value: orgPath(m), selected: Boolean(acting && acting.id === m.id) }, `${orgLabel(m)} (${m.role})`),
            ),
          ],
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
 * Act in another org: navigate to `/<path>/<same page>`, re-resolve the
 * session there (for the role), and re-render the current page from scratch —
 * whatever the page held belonged to the previous org. `null` is the personal
 * org.
 */
async function switchOrg(path) {
  const page = pageOf(route(window.location.pathname));
  const home = personalOrg(session);
  const target = path || (home ? orgPath(home) : null);
  window.history.pushState({}, '', target ? pagePath(target, page) : '/');
  await loadSession();
  mounted = null;
  pageState = {};
  await draw();
}

/** Client-side navigation to `page`, in the acting org. */
export function navigate(page) {
  const org = actingPath() || route(window.location.pathname).org;
  window.history.pushState({}, '', org ? pagePath(org, page) : '/');
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
  noAccess = false;
  window.history.pushState({}, '', '/');
  void draw();
}

/**
 * Resolve the session for the org the URL names, or leave it null (the login
 * page), then make the URL canonical.
 *
 * - `/<org>/<page>`: act in that org. If the server resolves it under another
 *   spelling (an id, different case), `replaceState` to `/<name>/<page>`; if
 *   it does not resolve at all, `noAccess`.
 * - `/` (landing): the server's default, the personal org →
 *   `/<personal>/devices`.
 * - legacy `/ui/<page>?org=<id>`: resolve the id → `/<name>/<page>`. Done
 *   here rather than as a server redirect because only the API can tell a
 *   member which org an id is, and it tells a non-member nothing.
 */
async function loadSession() {
  const r = route(window.location.pathname);
  let requested = r.org;
  if (r.legacy) {
    const q = new URLSearchParams(window.location.search).get('org');
    requested = q && q.trim() ? q.trim() : null;
  }
  noAccess = false;
  api.setOrg(requested);
  try {
    session = await api.get('/api/v1/session', { quiet: true });
  } catch {
    session = null;
    return;
  }
  if (!session) return;
  if (!session.org) {
    // Nonexistent, not a member, renamed away: one answer for all of them,
    // and the URL is left as the user typed it.
    noAccess = true;
    return;
  }
  const path = orgPath(session.org);
  // Pin the acting org explicitly once known, so every call names it.
  api.setOrg(path);
  if (r.page === 'notfound') return;
  if (r.legacy || r.page === 'landing' || r.org !== path) {
    window.history.replaceState({}, '', pagePath(path, pageOf(r)));
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
    const r = route(window.location.pathname);
    const current = actingPath();
    if (session && (r.legacy || r.page === 'landing' || (r.org && r.org !== current) || (noAccess && r.org))) {
      await loadSession();
      mounted = null;
      pageState = {};
    }
    await draw();
  })();
});

void (async () => {
  await loadSession();
  await draw();
})();
