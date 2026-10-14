// Path -> {page, org, legacy, params}. A pure function, so
// `web-tests/router.test.mjs` can assert the whole table without a DOM.
//
// Page URLs are `/<org>/<page>`: `<org>` is the acting org's path (for a
// personal org, the username) and is the one place the UI's acting org is
// chosen. `/` is the landing page (the shell moves to the personal org's
// devices page once the session is known), and the legacy
// `/ui/<page>?org=<id>` URLs are recognised so `app.mjs` can rewrite them.
//
// The set of pages here must match `PAGES` in `src/assets.rs`: the server
// answers exactly those pages with the shell — in both their bare and their
// trailing-slash spelling, since `route` below treats them as one page — and a
// path it does not know is a 404 rather than an HTML document. That is
// deliberate: it is what makes a typo'd asset URL surface as a broken import
// instead of as HTML parsed as JavaScript. `tests/ui_assets.rs` asserts the two
// lists have not drifted.

export const PAGES = ['devices', 'agents', 'approve', 'access', 'keys', 'org', 'audit'];

/** The nav bar's entries, in order. Paths come from `pagePath(org, page)`. */
export const NAV = [
  { page: 'devices', label: 'Devices' },
  { page: 'agents', label: 'Agents' },
  { page: 'approve', label: 'Approve' },
  { page: 'access', label: 'Access' },
  { page: 'keys', label: 'Auth keys' },
  { page: 'org', label: 'Org' },
  { page: 'audit', label: 'Audit' },
];

// The `<org>` segment the server serves a page for (`src/assets.rs`
// `org_segment_ok`, minus the reserved-name check, which the server does).
const ORG_SEGMENT = /^[A-Za-z0-9-]{1,64}$/;

/** The URL of `page` in org `org` (a path, or an id for a hand-written link). */
export function pagePath(org, page) {
  return `/${encodeURIComponent(String(org))}/${page}`;
}

/**
 * Resolve a pathname to a page.
 *
 * - `/` is `{page: 'landing'}`: no org yet, the app picks the personal one.
 * - `/ui`, `/ui/` and `/ui/<page>` are `legacy`: the org (if any) is in the
 *   query string as an id, and the app rewrites the URL once it resolves.
 * - `/<org>/<page>` (one trailing slash allowed) is that page in that org.
 * - Anything else is `notfound` — rendered client-side, because the server
 *   only serves the shell for the known routes and a stray path never gets
 *   here at all.
 */
export function route(pathname) {
  const path = String(pathname || '/');
  if (path === '/') return { page: 'landing', org: null, legacy: false, params: {} };
  if (path === '/ui' || path === '/ui/') return { page: 'devices', org: null, legacy: true, params: {} };
  const parts = path.replace(/\/$/, '').split('/');
  // ['', a, b]: exactly two segments.
  if (parts.length === 3 && parts[0] === '' && PAGES.includes(parts[2])) {
    if (parts[1] === 'ui') return { page: parts[2], org: null, legacy: true, params: {} };
    let org;
    try {
      org = decodeURIComponent(parts[1]);
    } catch {
      org = '';
    }
    if (ORG_SEGMENT.test(org)) return { page: parts[2], org, legacy: false, params: {} };
  }
  return { page: 'notfound', org: null, legacy: false, params: { path } };
}
