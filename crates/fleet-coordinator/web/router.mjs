// Path -> {page, params}. A pure function, so `web-tests/router.test.mjs` can
// assert the whole table without a DOM.
//
// The set of pages here must match `PAGES` in `src/assets.rs`: the server
// answers exactly those pages with the shell — in both their bare and their
// trailing-slash spelling, since `route` below treats them as one page — and a
// path it does not know is a 404 rather than an HTML document. That is
// deliberate: it is what makes a typo'd asset URL surface as a broken import
// instead of as HTML parsed as JavaScript. `tests/ui_assets.rs` asserts the two
// lists have not drifted.

export const PAGES = ['devices', 'agents', 'approve', 'access', 'keys', 'org', 'audit'];

/** The nav bar's entries, in order. */
export const NAV = [
  { page: 'devices', path: '/ui/devices', label: 'Devices' },
  { page: 'agents', path: '/ui/agents', label: 'Agents' },
  { page: 'approve', path: '/ui/approve', label: 'Approve' },
  { page: 'access', path: '/ui/access', label: 'Access' },
  { page: 'keys', path: '/ui/keys', label: 'Auth keys' },
  { page: 'org', path: '/ui/org', label: 'Org' },
  { page: 'audit', path: '/ui/audit', label: 'Audit' },
];

/**
 * Resolve a pathname to a page.
 *
 * `/ui` and `/ui/` are the devices page (the landing page after login).
 * Anything else under `/ui/` that is not a known page is `notfound` — rendered
 * client-side, because the server only serves the shell for the known routes
 * and a stray path never gets here at all.
 */
export function route(pathname) {
  const path = String(pathname || '/ui/');
  if (path === '/ui' || path === '/ui/' || path === '/') return { page: 'devices', params: {} };
  if (!path.startsWith('/ui/')) return { page: 'notfound', params: { path } };
  const rest = path.slice('/ui/'.length).replace(/\/+$/, '');
  if (PAGES.includes(rest)) return { page: rest, params: {} };
  return { page: 'notfound', params: { path } };
}
