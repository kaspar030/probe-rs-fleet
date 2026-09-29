// The fetch wrapper: what it attaches, and what it must never attach.
//
// Driven with a fake `fetch` and a fake cookie jar, so there is no browser and
// no network — the wrapper's contract is entirely about headers and error
// mapping, and both are observable from here.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { request, cookie, ApiError, describe, setUnauthorizedHandler, setOrg, withOrg } from '../web/api.mjs';

/** A `fetch` that records its calls and answers with a canned response. */
function fakeFetch(response) {
  const calls = [];
  const impl = async (path, init) => {
    calls.push({ path, init });
    return {
      status: response.status ?? 200,
      ok: (response.status ?? 200) < 400,
      text: async () => response.body ?? '',
    };
  };
  impl.calls = calls;
  return impl;
}

const JAR = 'prfs_csrf=deadbeef; other=1';

test('a cookie is read out of a jar, and a missing one is null', () => {
  assert.equal(cookie('prfs_csrf', JAR), 'deadbeef');
  assert.equal(cookie('other', JAR), '1');
  assert.equal(cookie('prfs_session', JAR), null);
  assert.equal(cookie('prfs_csrf', ''), null);
});

test('a GET carries no CSRF header and no body', async () => {
  const f = fakeFetch({ status: 200, body: '{"ok":true}' });
  const body = await request('GET', '/api/v1/session', null, { fetch: f, jar: JAR });
  assert.deepEqual(body, { ok: true });
  const { init } = f.calls[0];
  assert.equal(init.headers['X-Fleet-Csrf'], undefined);
  assert.equal(init.body, undefined);
  assert.equal(init.credentials, 'same-origin');
});

test('every mutating method carries the CSRF cookie as a header', async () => {
  for (const method of ['POST', 'PATCH', 'DELETE']) {
    const f = fakeFetch({ status: 200, body: '{}' });
    await request(method, '/api/v1/grants', method === 'DELETE' ? null : {}, { fetch: f, jar: JAR });
    assert.equal(f.calls[0].init.headers['X-Fleet-Csrf'], 'deadbeef', method);
  }
});

test('with no CSRF cookie the header is simply absent, not empty', async () => {
  const f = fakeFetch({ status: 200, body: '{}' });
  await request('POST', '/api/v1/session/logout', {}, { fetch: f, jar: '' });
  assert.equal(f.calls[0].init.headers['X-Fleet-Csrf'], undefined);
});

test('a 204 is null, not a parse error', async () => {
  const f = fakeFetch({ status: 204, body: '' });
  assert.equal(await request('DELETE', '/api/v1/nodes/x', null, { fetch: f, jar: JAR }), null);
});

test('an error body becomes an ApiError carrying the server code', async () => {
  const f = fakeFetch({ status: 403, body: '{"error":"forbidden"}' });
  await assert.rejects(
    () => request('POST', '/api/v1/grants', {}, { fetch: f, jar: JAR }),
    (err) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.status, 403);
      assert.equal(err.code, 'forbidden');
      return true;
    },
  );
});

test('a 401 triggers the login transition exactly once, and still throws', async () => {
  let transitions = 0;
  setUnauthorizedHandler(() => { transitions += 1; });
  const f = fakeFetch({ status: 401, body: '{"error":"unauthorized"}' });
  await assert.rejects(() => request('GET', '/api/v1/boards', null, { fetch: f, jar: JAR }));
  assert.equal(transitions, 1);
  // `quiet` is for the bootstrap probe, which must not bounce the page while
  // it is deciding whether to render the login form in the first place.
  await assert.rejects(() => request('GET', '/api/v1/session', null, { fetch: f, jar: JAR, quiet: true }));
  assert.equal(transitions, 1);
  setUnauthorizedHandler(() => {});
});

test('the coarse error codes all have human copy', () => {
  for (const code of ['forbidden', 'not_found', 'invalid_request', 'conflict', 'server_error', 'upstream_error']) {
    const text = describe(new ApiError(400, code, null));
    assert.ok(text.length > 10, code);
    assert.notEqual(text, code, `${code} must not be shown raw`);
  }
});

test('every /api/v1 call carries the acting org, and only /api/v1 calls do', async () => {
  setOrg('01J0000000000000000000ORG2');
  try {
    const f = fakeFetch({ status: 200, body: '{}' });
    await request('GET', '/api/v1/boards', null, { fetch: f, jar: JAR });
    await request('GET', '/api/v1/audit?board=dk-3', null, { fetch: f, jar: JAR });
    await request('POST', '/api/v1/nodes/pending/ABCD', {}, { fetch: f, jar: JAR, org: 'other org' });
    await request('GET', '/auth/providers', null, { fetch: f, jar: JAR });
    assert.deepEqual(f.calls.map((c) => c.path), [
      '/api/v1/boards?org=01J0000000000000000000ORG2',
      '/api/v1/audit?board=dk-3&org=01J0000000000000000000ORG2',
      '/api/v1/nodes/pending/ABCD?org=other%20org',
      '/auth/providers',
    ]);
  } finally {
    setOrg(null);
  }
  const f = fakeFetch({ status: 200, body: '{}' });
  await request('GET', '/api/v1/session', null, { fetch: f, jar: JAR });
  assert.equal(f.calls[0].path, '/api/v1/session', 'no org: the server default (personal org)');
  assert.equal(withOrg('/api/v1/x', null), '/api/v1/x');
});
