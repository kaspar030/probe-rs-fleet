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

import { route, PAGES, NAV, pagePath } from '../web/router.mjs';

test('the root is the landing page, with no org', () => {
  assert.deepEqual(route('/'), { page: 'landing', org: null, legacy: false, params: {} });
});

test('every page is routed at /<org>/<page>, in both spellings', () => {
  for (const page of PAGES) {
    for (const path of [`/alice/${page}`, `/alice/${page}/`]) {
      const r = route(path);
      assert.equal(r.page, page, path);
      assert.equal(r.org, 'alice', path);
      assert.equal(r.legacy, false, path);
    }
  }
  // An id is a valid segment too (a hand-written link); the app canonicalises it.
  assert.equal(route('/01J0000000000000000000ORG2/keys').org, '01J0000000000000000000ORG2');
  assert.equal(route('/acme-labs/org').org, 'acme-labs');
});

test('every page has a nav entry, and nav links are pagePath', () => {
  assert.deepEqual(
    NAV.map((n) => n.page),
    PAGES,
    'the nav bar and the page list must not drift',
  );
  for (const entry of NAV) {
    const path = pagePath('acme', entry.page);
    assert.equal(path, `/acme/${entry.page}`);
    assert.deepEqual(route(path), { page: entry.page, org: 'acme', legacy: false, params: {} });
  }
  assert.ok(!NAV.some((n) => 'path' in n), 'nav entries carry no org-less path');
});

test('pagePath encodes the org into one segment', () => {
  assert.equal(pagePath('a/b?c', 'devices'), '/a%2Fb%3Fc/devices');
});

test('legacy /ui URLs are recognised so the app can rewrite them', () => {
  for (const [path, page] of [['/ui', 'devices'], ['/ui/', 'devices'], ['/ui/devices', 'devices'], ['/ui/approve/', 'approve']]) {
    assert.deepEqual(route(path), { page, org: null, legacy: true, params: {} }, path);
  }
});

test('the org page is routed and in the nav', () => {
  assert.ok(PAGES.includes('org'));
  assert.equal(route('/alice/org').page, 'org');
  assert.deepEqual(NAV.find((n) => n.page === 'org'), { page: 'org', label: 'Org' });
});

test('an unknown path is the not-found page, never a real one', () => {
  for (const path of [
    '/ui/nope', '/alice/nope', '/alice/devices/extra', '/alice', '/alice/', '/healthz',
    '/api/v1/session', '/a.b/devices', '/%2e%2e/devices', '/a%2Fb/devices', '//devices',
  ]) {
    assert.equal(route(path).page, 'notfound', path);
    assert.equal(route(path).org, null, path);
  }
});

test('the not-found result carries the path it could not resolve', () => {
  assert.equal(route('/alice/nope').params.path, '/alice/nope');
});
