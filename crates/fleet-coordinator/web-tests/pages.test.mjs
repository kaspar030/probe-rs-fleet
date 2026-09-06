// Each page's `render()` against fixture API responses.
//
// The smoke test the task asks for, and it needs no DOM: pages are pure
// functions from state to a vnode tree (see `web/dom.mjs`), so these assert
// over the returned objects. No jsdom, no stubbing, no dependency.
//
// The three assertions that are not smoke:
//
//   * the approval page renders the server's `warning` field **verbatim**, and
//     not a copy of the sentence;
//   * the access page's op list reflects `enforced_by` from the fixture,
//     including `nobody`;
//   * the keys page's shown-once panel contains the key and says it will not be
//     shown again.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { textOf, find, findAll } from '../web/dom.mjs';
import * as login from '../web/pages/login.mjs';
import * as devices from '../web/pages/devices.mjs';
import * as agents from '../web/pages/agents.mjs';
import * as approve from '../web/pages/approve.mjs';
import * as access from '../web/pages/access.mjs';
import * as keys from '../web/pages/keys.mjs';
import * as audit from '../web/pages/audit.mjs';

const ADMIN = { user: 'gh-1', login: 'alice', org: 'gh-1', org_slug: 'alice', role: 'admin' };
const MEMBER = { user: 'gh-2', login: 'bob', org: 'gh-1', org_slug: 'alice', role: 'member' };

const BOARD = {
  board: { key: 'gh-1/gh-1/rpi-1/dk-3', org: 'gh-1', node: 'gh-1/rpi-1', name: 'dk-3' },
  node: 'gh-1/rpi-1',
  chip: 'nRF52840_xxAA',
  model: 'nrf52840dk',
  tags: ['lab', 'nrf'],
  exclusive: true,
  power: 'uhubctl',
  availability: 'leased',
  holder: { key: 'gh-1:user:gh-2', org: 'gh-1', kind: 'user', id: 'gh-2' },
  lease: 42,
  expires: 1800000000,
};

const LIMITS = {
  max_ttl_secs: 31536000,
  expires_optional: false,
  now: 1700000000,
  min_revoke_prefix: 8,
  auth_key_max_ttl_secs: 2592000,
  ops: [
    { op: 'attach', enforced_by: 'agent', implies_attach: false },
    { op: 'gdb', enforced_by: 'agent', implies_attach: true },
    { op: 'power-cycle', enforced_by: 'coordinator', implies_attach: false },
    { op: 'flash', enforced_by: 'nobody', implies_attach: true },
    { op: 'erase', enforced_by: 'nobody', implies_attach: true },
    { op: 'reset', enforced_by: 'nobody', implies_attach: true },
  ],
};

/** Every button label in a tree. */
const labels = (tree) => findAll(tree, (n) => n.tag === 'button').map((n) => n.children.join(''));

// ---------------------------------------------------------------------------

test('login offers whichever flow the deployment reports', () => {
  const code = login.render({ method: 'authorization_code' });
  const link = find(code, (n) => n.tag === 'a');
  assert.equal(link.attrs.href, '/auth/github/start');

  const device = login.render({ method: 'device', device: { user_code: 'ABCD-1234', verification_uri: 'https://github.com/login/device', interval: 5 }, polling: true });
  assert.match(textOf(device), /ABCD-1234/);

  const none = login.render({ method: 'none' });
  assert.match(textOf(none), /coordinator user-token/);
});

test('devices renders the inventory and gates its actions by role', () => {
  const asHolder = devices.render({ boards: [BOARD], session: MEMBER });
  const text = textOf(asHolder);
  assert.match(text, /dk-3/);
  assert.match(text, /nRF52840_xxAA/);
  assert.match(text, /nrf52840dk/);
  assert.match(text, /gh-1:user:gh-2/);
  assert.ok(labels(asHolder).includes('Release'), 'the holder sees Release');

  // A member who is not the holder does not; an admin does. Hiding is UX —
  // `tests/ui_authz.rs` is the half that matters.
  const asStranger = devices.render({ boards: [BOARD], session: { ...MEMBER, user: 'gh-9' } });
  assert.ok(!labels(asStranger).includes('Release'));
  const asAdmin = devices.render({ boards: [BOARD], session: ADMIN });
  assert.ok(labels(asAdmin).includes('Release'));
});

test('devices disables power-cycle for a board with no power control', () => {
  const tree = devices.render({ boards: [{ ...BOARD, power: 'none' }], session: ADMIN });
  const button = find(tree, (n) => n.tag === 'button' && n.children.join('') === 'Power-cycle');
  assert.equal(button.attrs.disabled, true);
});

// A board with no declared model renders an em dash rather than "undefined":
// it is the visible signal that no `board=` selector can reach it.
test('devices renders a missing board model as a dash', () => {
  const tree = devices.render({ boards: [{ ...BOARD, model: null }], session: ADMIN });
  assert.ok(!textOf(tree).includes('undefined'));
  assert.ok(!textOf(tree).includes('nrf52840dk'));
});

test('agents offers tags and adopt, never a rename', () => {
  const node = {
    id: 'gh-1/rpi-1', name: 'rpi-1', tags: ['lab'], adopt: 'declared',
    owner: 'gh-1', last_seen: 1700000000, created_at: 1600000000, online: true, boards: ['dk-3'],
  };
  const tree = agents.render({ nodes: [node], session: ADMIN, editing: 'rpi-1' });
  const inputs = findAll(tree, (n) => n.tag === 'input' || n.tag === 'select').map((n) => n.attrs.name);
  assert.deepEqual(inputs.sort(), ['adopt', 'tags']);
  assert.match(textOf(tree), /cannot be changed/);
  assert.match(textOf(tree), /Renaming is not supported/);
});

test('approve renders the server warning verbatim, not a copy of the sentence', () => {
  // Deliberately not the production string: the page must render the *field*.
  const warning = 'SERVER-SUPPLIED WARNING TEXT, RENDERED VERBATIM.';
  const pending = {
    user_code: 'ABCD-1234', node_name: 'rpi-9', tags: ['lab'], adopt: 'declared',
    source_ip: '10.0.0.9', created_at: 1700000000, expires: 1700000900,
    org: 'gh-1', state: 'pending', warning,
  };
  const tree = approve.render({ pending, code: 'ABCD-1234', replace: false });
  const text = textOf(tree);
  assert.ok(text.includes(warning), 'the warning field must be rendered');
  assert.match(text, /rpi-9/);
  assert.match(text, /10\.0\.0\.9/);
  assert.ok(labels(tree).includes('Approve') && labels(tree).includes('Deny'));

  // A server that sent no warning must produce a visibly empty box, never a
  // frontend copy of the sentence.
  const bare = approve.render({ pending: { ...pending, warning: undefined } });
  assert.ok(!textOf(bare).includes('ONLY if you started'), 'the sentence must not be hardcoded here');
});

test('approve names the collision before the confirm, not after', () => {
  const tree = approve.render({
    pending: {
      user_code: 'ABCD-1234', node_name: 'rpi-1', tags: [], adopt: 'declared',
      created_at: 1, expires: 2, state: 'pending', warning: 'w', collides_with: 'gh-1/rpi-1',
    },
  });
  assert.match(textOf(tree), /already has a node called rpi-1/);
});

test('access builds its op list from the server, enforcement and all', () => {
  const tree = access.render({
    grants: [], limits: LIMITS, session: ADMIN,
    form: { granteeKind: 'login', grantee: '', selector: [{ kind: 'tag', value: 'lab' }], ops: ['attach'], expires: '' },
  });
  assert.deepEqual(access.checkboxNames(tree), LIMITS.ops.map((o) => `op_${o.op}`));
  const text = textOf(tree);
  assert.match(text, /enforced by the agent/);
  assert.match(text, /enforced by the coordinator/);
  assert.match(text, /not enforced anywhere/);
  assert.match(text, /implies attach/);
  // The exact string that will be sent is shown, not a structured summary.
  assert.match(text, /tag=lab/);
});

test('access bounds the expiry from the limits endpoint, using the server clock', () => {
  const tree = access.render({
    grants: [], limits: LIMITS, session: ADMIN,
    form: { granteeKind: 'login', grantee: '', selector: [], ops: [], expires: '' },
  });
  const input = find(tree, (n) => n.tag === 'input' && n.attrs.name === 'expires');
  assert.equal(input.attrs.min, access.localInput(LIMITS.now + 60));
  assert.equal(input.attrs.max, access.localInput(LIMITS.now + LIMITS.max_ttl_secs));
});

test('access hides the create form from a member and says why', () => {
  const tree = access.render({ grants: [], limits: LIMITS, session: MEMBER, form: {} });
  assert.equal(find(tree, (n) => n.tag === 'form'), null);
  assert.match(textOf(tree), /admin-only/);
});

test('the selector is the canonical string a CLI would send', () => {
  // `board=` is the board MODEL; `id=` is the one board.
  assert.equal(
    access.selectorString([{ kind: 'board', value: 'nrf52840dk' }, { kind: 'tag', value: 'lab' }]),
    'board=nrf52840dk && tag=lab',
  );
  assert.equal(
    access.selectorString([{ kind: 'id', value: 'dk-3' }]),
    'id=dk-3',
  );
  assert.equal(access.selectorString([{ kind: 'tag', value: '  ' }]), '');
  // A CI repo grantee needs the prefix `resolve_grantee` matches; a bare
  // owner/name resolves to nothing at all.
  assert.equal(access.granteeString('repo', 'ariel-os/probe-rs-fleet'), 'repo:ariel-os/probe-rs-fleet');
  assert.equal(access.granteeString('login', 'alice'), 'alice');
});

test('keys shows a minted key once, and says it will not be shown again', () => {
  const minted = {
    key: 'prffk1_SECRETVALUE', key_hash: 'a'.repeat(64), org: 'gh-1',
    tags: ['lab'], single_use: true, purpose: 'node', expires: 1800000000,
  };
  const tree = keys.render({
    keys: [], limits: LIMITS, session: ADMIN, minted,
    form: { purpose: 'node', tags: '', ttl_secs: 86400, multi_use: false },
  });
  const panel = keys.secretPanel(tree);
  assert.ok(panel, 'the shown-once panel must exist');
  assert.equal(panel.children.join(''), minted.key);
  assert.match(textOf(tree), /only time it will be shown/);
});

test('keys bounds the TTL from the limits endpoint', () => {
  const tree = keys.render({
    keys: [], limits: LIMITS, session: ADMIN, minted: null,
    form: { purpose: 'node', tags: '', ttl_secs: 86400, multi_use: false },
  });
  const ttl = find(tree, (n) => n.tag === 'input' && n.attrs.name === 'ttl_secs');
  assert.equal(ttl.attrs.max, LIMITS.auth_key_max_ttl_secs);
  assert.match(textOf(tree), /At most 30 days/);
});

test('audit says a 403 in words and admits it does not page', () => {
  const denied = audit.render({ denied: true, session: MEMBER });
  assert.match(textOf(denied), /cannot read the audit log/);

  const lines = audit.render({
    session: ADMIN,
    lines: [{ ts: 1700000000, action: 'lease.grant', board: 'dk-3', detail: 'gh-1:user:gh-2' }],
  });
  const text = textOf(lines);
  assert.match(text, /lease\.grant/);
  assert.match(text, /no paging/);
});

test('every page renders an empty state without throwing', () => {
  assert.ok(textOf(devices.render({ boards: [], session: MEMBER })).length > 0);
  assert.ok(textOf(agents.render({ nodes: [], session: MEMBER })).length > 0);
  assert.ok(textOf(approve.render({ pending: null })).length > 0);
  assert.ok(textOf(access.render({ grants: [], limits: null, session: ADMIN, form: {} })).length > 0);
  assert.ok(textOf(keys.render({ keys: [], limits: null, session: MEMBER, form: { purpose: 'node', tags: '', ttl_secs: 1, multi_use: false } })).length > 0);
  assert.ok(textOf(audit.render({ lines: [], session: ADMIN })).length > 0);
  assert.ok(textOf(login.render({ method: null })).length > 0);
});
