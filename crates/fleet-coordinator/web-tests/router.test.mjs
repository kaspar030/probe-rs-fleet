// The router table, asserted with no DOM.
//
// `node --test web-tests/router.test.mjs` — no npm, no package.json, no
// lockfile. Every frontend module is `.mjs`, which is unambiguous to node on
// every version with no configuration at all; a `.js` module here would be
// resolved as CommonJS on node < 22.7 (and on any node whose upward walk finds
// a package scope it dislikes), and the whole suite would fail with a syntax
// error rather than skip.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { route, PAGES, NAV } from '../web/router.mjs';

test('the landing paths resolve to devices', () => {
  for (const path of ['/', '/ui', '/ui/']) {
    assert.equal(route(path).page, 'devices', path);
  }
});

test('every page has a route, and every route a nav entry', () => {
  for (const page of PAGES) {
    assert.equal(route(`/ui/${page}`).page, page);
    // A trailing slash is the same page: a user who types one should not 404.
    assert.equal(route(`/ui/${page}/`).page, page);
  }
  assert.deepEqual(
    NAV.map((n) => n.page),
    PAGES,
    'the nav bar and the page list must not drift',
  );
  for (const entry of NAV) {
    assert.equal(route(entry.path).page, entry.page);
  }
});

test('an unknown path is the not-found page, never a real one', () => {
  for (const path of ['/ui/nope', '/ui/devices/extra', '/healthz', '/api/v1/session']) {
    assert.equal(route(path).page, 'notfound', path);
  }
});

test('the not-found result carries the path it could not resolve', () => {
  assert.equal(route('/ui/nope').params.path, '/ui/nope');
});
