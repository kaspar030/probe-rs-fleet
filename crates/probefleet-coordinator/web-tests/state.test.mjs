// A page's view state must survive a re-render of that page, and must be
// dropped when the user leaves it.
//
// Both halves are real bugs this file exists to prevent, and both were found by
// review rather than by running the UI:
//
//   * `load()` runs again on every `reload()`, so anything a handler stores in
//     a local is rebuilt empty on the very next render. The Edit form would set
//     `editing` and then re-render without it; the approve page would
//     look up a code and immediately forget it. State that must survive a
//     re-render lives on the context object `app.mjs` owns.
//   * that object is per *mounted page*, not per render, and is dropped whole
//     on navigation — which is what makes the keys page's shown-once panel
//     honest: there is no second reference to a minted key anywhere, so leaving
//     the page is what deletes it.
//
// These tests drive the pages the way `app.mjs` does: one `ctx` object, reused
// across `load()` calls, with a `reload` that re-invokes `load`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { textOf, find, findAll } from '../web/dom.mjs';
import * as agents from '../web/pages/agents.mjs';
import * as approve from '../web/pages/approve.mjs';
import * as keys from '../web/pages/keys.mjs';

const ORG = '01J0000000000000000000ORG1';
const TEAM = '01J0000000000000000000ORG2';
const SESSION = {
  user_id: '01J0000000000000000000USR1', username: 'alice',
  memberships: [{ id: ORG, name: 'alice', role: 'admin' }, { id: TEAM, name: 'ariel-os', role: 'member' }],
  org: { id: ORG, name: 'alice', role: 'admin' }, expires: 1800000000,
};

/**
 * A context that behaves like `app.mjs`'s: stable identity, `reload()`
 * re-invokes the page's own `load()` and keeps the newest tree.
 */
function makeCtx(page, responses) {
  const ctx = {
    session: SESSION,
    api: {
      get: async (path) => {
        if (!(path in responses)) throw new Error(`unstubbed GET ${path}`);
        return responses[path];
      },
      posts: [],
      post: async (path, body, options) => {
        ctx.api.posts.push({ path, body, options });
        if (!(path in responses)) throw new Error(`unstubbed POST ${path}`);
        return typeof responses[path] === 'function' ? responses[path](body, options) : responses[path];
      },
      // The acting org as `app.mjs` sets it: the URL's org *path*, not an id.
      currentOrg: () => 'alice',
      patch: async () => ({}),
      del: async () => null,
      describe: (e) => String(e && e.message ? e.message : e),
    },
    navigate: () => {},
  };
  ctx.reload = async () => {
    ctx.tree = await page.load(ctx);
    return ctx.tree;
  };
  return ctx;
}

const NODE = {
  id: `${ORG}/rpi-1`, name: 'rpi-1', tags: ['lab'], adopt: 'declared',
  owner: SESSION.user_id, last_seen: 1700000000, created_at: 1600000000, online: true, boards: [],
};

test('the agents edit form survives the re-render that opens it', async () => {
  const ctx = makeCtx(agents, { '/api/v1/nodes': [NODE] });
  let tree = await ctx.reload();
  // Closed: no form yet.
  assert.equal(find(tree, (n) => n.tag === 'form'), null);

  // Pressing Edit stores the row and re-renders. If `editing` lived in a local,
  // the second render would rebuild it as null and the form would never appear.
  const edit = find(tree, (n) => n.tag === 'button' && n.children.join('') === 'Edit');
  await edit.on.click();
  tree = ctx.tree;
  assert.ok(find(tree, (n) => n.tag === 'form'), 'the edit form must be open after a reload');
  assert.match(textOf(tree), /cannot be changed/);
});

test('an inspected registration survives the re-render that displays it', async () => {
  const warning = 'SERVER WARNING';
  const pending = {
    user_code: 'ABCD-1234', node_name: 'rpi-9', tags: [], adopt: 'declared',
    created_at: 1, expires: 2, state: 'pending', org: ORG, warning,
  };
  const ctx = makeCtx(approve, { '/api/v1/nodes/pending/ABCD-1234': pending });
  let tree = await ctx.reload();
  assert.ok(!textOf(tree).includes(warning), 'nothing is shown before a lookup');

  const form = find(tree, (n) => n.tag === 'form');
  await form.on.submit({ preventDefault() {}, target: { elements: { code: { value: 'ABCD-1234' } } } });
  tree = ctx.tree;
  assert.ok(textOf(tree).includes(warning), 'the inspected row must survive the reload');
  assert.match(textOf(tree), /rpi-9/);
});

test('approval acts in the chosen target org and names it in the confirmation', async () => {
  const pendingIn = (org) => ({
    user_code: 'ABCD-1234', node_name: 'rpi-9', tags: [], adopt: 'declared',
    created_at: 1, expires: 2, state: 'pending', org, warning: 'w',
  });
  const ctx = makeCtx(approve, {
    '/api/v1/nodes/pending/ABCD-1234': (body, options) =>
      ({ ...pendingIn(options.org), state: body.decision === 'approve' ? 'approved' : 'pending' }),
  });
  let tree = await ctx.reload();
  // Defaults to the org the UI acts in.
  const picker = find(tree, (n) => n.tag === 'select' && n.attrs.name === 'org');
  assert.equal(find(picker, (n) => n.tag === 'option' && n.attrs.selected).attrs.value, ORG);

  // Pick the team org, then look up and approve.
  await picker.on.change({ target: { value: TEAM } });
  tree = ctx.tree;
  await find(tree, (n) => n.tag === 'form').on.submit({ preventDefault() {}, target: { elements: { code: { value: 'ABCD-1234' } } } });
  tree = ctx.tree;
  assert.match(textOf(tree), /ariel-os/);
  const approveButton = find(tree, (n) => n.tag === 'button' && n.children.join('') === 'Approve into ariel-os');
  assert.ok(approveButton, 'the confirm names the target org');
  await approveButton.on.click();
  tree = ctx.tree;

  assert.deepEqual(ctx.api.posts.map((p) => [p.body.decision, p.options.org]), [['inspect', TEAM], ['approve', TEAM]]);
  assert.match(textOf(tree), /Approved into ariel-os/);
});

test('changing the target org drops a looked-up registration', async () => {
  const ctx = makeCtx(approve, {
    '/api/v1/nodes/pending/ABCD-1234': (_b, o) => ({
      user_code: 'ABCD-1234', node_name: 'rpi-9', tags: [], adopt: 'declared',
      created_at: 1, expires: 2, state: 'pending', org: o.org, warning: 'SERVER WARNING',
    }),
  });
  let tree = await ctx.reload();
  await find(tree, (n) => n.tag === 'form').on.submit({ preventDefault() {}, target: { elements: { code: { value: 'ABCD-1234' } } } });
  tree = ctx.tree;
  assert.match(textOf(tree), /SERVER WARNING/);
  await find(tree, (n) => n.tag === 'select' && n.attrs.name === 'org').on.change({ target: { value: TEAM } });
  assert.ok(!textOf(ctx.tree).includes('SERVER WARNING'));
});

test('an empty code is refused before any request, with a reason', async () => {
  const ctx = makeCtx(approve, {});
  let tree = await ctx.reload();
  const form = find(tree, (n) => n.tag === 'form');
  await form.on.submit({ preventDefault() {}, target: { elements: { code: { value: '   ' } } } });
  tree = ctx.tree;
  assert.match(textOf(tree), /Enter the code/);
});

test('a minted key survives its own re-render and is dropped on dismiss', async () => {
  const minted = { key: 'prfk1_SECRET', key_hash: 'b'.repeat(64), purpose: 'node', single_use: true, expires: 1800000000 };
  const ctx = makeCtx(keys, {
    '/api/v1/auth-keys': { org: ORG, keys: [] },
    '/api/v1/grants/limits': { now: 1700000000, max_ttl_secs: 100, ops: [], min_revoke_prefix: 8, auth_key_max_ttl_secs: 2592000, expires_optional: false },
  });
  // The mint call answers with the secret.
  ctx.api.post = async () => minted;

  let tree = await ctx.reload();
  assert.equal(keys.secretPanel(tree), null, 'nothing is shown before minting');

  // Driven the way a browser does: "Mint key" is `type="submit"`, so the
  // handler is the form's, not the button's.
  const form = find(tree, (n) => n.tag === 'form');
  await form.on.submit({ preventDefault() {} });
  tree = ctx.tree;
  const panel = keys.secretPanel(tree);
  assert.ok(panel, 'the key must survive the reload that displays it');
  assert.equal(panel.children.join(''), minted.key);

  // Dismiss drops it, and it is gone from the rendered tree entirely.
  const dismiss = find(tree, (n) => n.tag === 'button' && n.children.join('') === 'Dismiss');
  await dismiss.on.click();
  tree = ctx.tree;
  assert.equal(keys.secretPanel(tree), null);
  assert.ok(!textOf(tree).includes(minted.key), 'the key must not linger anywhere in the tree');
});

test('a CI key with no tags is refused client-side, with the reason', async () => {
  const ctx = makeCtx(keys, {
    '/api/v1/auth-keys': { org: ORG, keys: [] },
    '/api/v1/grants/limits': { now: 1, max_ttl_secs: 100, ops: [], min_revoke_prefix: 8, auth_key_max_ttl_secs: 2592000, expires_optional: false },
  });
  let called = false;
  ctx.api.post = async () => { called = true; return {}; };

  await ctx.reload();
  ctx.keyForm.purpose = 'ci';
  ctx.keyForm.tags = '';
  let tree = await ctx.reload();
  const form = find(tree, (n) => n.tag === 'form');
  await form.on.submit({ preventDefault() {} });
  tree = ctx.tree;
  assert.equal(called, false, 'the request must not be sent');
  // The server would refuse it too; saying so here is UX, not enforcement.
  assert.match(textOf(tree), /whole fleet/);
});

test('every action handler a page renders is a function, not a string', () => {
  // The CSP has no `unsafe-inline`, so a handler that ended up as an attribute
  // would be silently dropped by the browser. `dom.mjs` only attaches the `on`
  // channel, so this asserts pages actually use it.
  const tree = agents.render({ nodes: [NODE], session: SESSION, editing: 'rpi-1' });
  const interactive = findAll(tree, (n) => n.tag === 'button' || n.tag === 'form' || n.tag === 'select');
  assert.ok(interactive.length > 0);
  for (const node of interactive) {
    for (const [event, handler] of Object.entries(node.on || {})) {
      assert.equal(typeof handler, 'function', `${node.tag}.${event}`);
    }
    for (const key of Object.keys(node.attrs || {})) {
      assert.ok(!key.startsWith('on'), `${node.tag} has an ${key} attribute`);
      assert.notEqual(key, 'style', `${node.tag} has a style attribute`);
    }
  }
});

test('org actions post the contract bodies and switch into a created org', async () => {
  const { load } = await import('../web/pages/org.mjs');
  const members = [{ user_id: SESSION.user_id, username: 'alice', role: 'admin' }, { user_id: 'u2', username: 'bob', role: 'member' }];
  const switched = [];
  const deleted = [];
  const ctx = makeCtx({ load }, {
    '/api/v1/org/members': () => null,
    '/api/v1/orgs': () => ({ id: TEAM, name: 'team', role: 'admin' }),
  });
  ctx.session = { ...SESSION, can_create_orgs: true };
  ctx.api.get = async (path) => { assert.equal(path, '/api/v1/org/members'); return members; };
  ctx.api.del = async (path) => { deleted.push(path); return null; };
  ctx.switchOrg = async (id) => { switched.push(id); };
  const prevWindow = globalThis.window;
  globalThis.window = { confirm: () => true };
  try {
    let tree = await ctx.reload();
    const roleSelects = findAll(tree, (n) => n.tag === 'select' && n.attrs.name === 'role');
    await roleSelects[1].on.change({ target: { value: 'admin' } });
    assert.deepEqual(ctx.api.posts.at(-1), { path: '/api/v1/org/members', body: { username: 'bob', role: 'admin' }, options: undefined });
    assert.deepEqual(switched, [], 'changing someone else does not touch the session');

    tree = ctx.tree;
    const remove = findAll(tree, (n) => n.tag === 'button' && n.children.join('') === 'Remove');
    await remove[1].on.click();
    assert.deepEqual(deleted, ['/api/v1/org/members/bob']);

    // Removing yourself drops you back to the default org.
    await remove[0].on.click();
    assert.deepEqual(switched, [null]);

    const create = find(ctx.tree, (n) => n.tag === 'form' && n.attrs.name === 'create-org');
    await create.on.submit({ preventDefault() {}, target: { elements: { name: { value: 'team' } } } });
    assert.deepEqual(ctx.api.posts.at(-1), { path: '/api/v1/orgs', body: { name: 'team' }, options: { org: null } });
    assert.deepEqual(switched, [null, 'team'], 'a created org is switched to by path');
  } finally {
    globalThis.window = prevWindow;
  }
});

test('org rename posts the new name and delete drops back to the default org', async () => {
  const { load } = await import('../web/pages/org.mjs');
  const switched = [];
  const deleted = [];
  const ctx = makeCtx({ load }, {
    '/api/v1/org/rename': () => ({ id: TEAM, name: 'acme2', role: 'admin', personal: false }),
  });
  ctx.session = { ...SESSION, org: { id: TEAM, name: 'acme', role: 'admin', personal: false } };
  ctx.api.get = async () => [];
  ctx.api.del = async (path) => { deleted.push(path); return null; };
  ctx.switchOrg = async (id) => { switched.push(id); };
  const prevWindow = globalThis.window;
  let confirmed = [];
  globalThis.window = { confirm: (m) => { confirmed.push(m); return true; } };
  try {
    const tree = await ctx.reload();
    const rename = find(tree, (n) => n.tag === 'form' && n.attrs.name === 'rename-org');
    await rename.on.submit({ preventDefault() {}, target: { elements: { name: { value: ' acme2 ' } } } });
    assert.deepEqual(ctx.api.posts.at(-1), { path: '/api/v1/org/rename', body: { name: 'acme2' }, options: undefined });
    assert.deepEqual(switched, ['acme2'], 'a renamed org is switched to by its new path');

    const del = find(ctx.tree, (n) => n.tag === 'button' && n.attrs.name === 'delete-org');
    await del.on.click();
    assert.match(confirmed.at(-1), /acme/);
    assert.deepEqual(deleted, ['/api/v1/org']);
    assert.deepEqual(switched, ['acme2', null]);

    // Declining the confirm does nothing.
    globalThis.window = { confirm: () => false };
    await del.on.click();
    assert.deepEqual(deleted, ['/api/v1/org']);
  } finally {
    globalThis.window = prevWindow;
  }
});
