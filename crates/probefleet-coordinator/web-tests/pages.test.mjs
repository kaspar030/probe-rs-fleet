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
import * as org from '../web/pages/org.mjs';

// `GET /api/v1/session`'s shape (src/api.rs `SessionView`).
const ORG = '01J0000000000000000000ORG1';
const TEAM = '01J0000000000000000000ORG2';
const ADMIN = {
  user_id: '01J0000000000000000000USR1', username: 'alice',
  memberships: [{ id: ORG, name: 'alice', role: 'admin' }, { id: TEAM, name: 'ariel-os', role: 'member' }],
  org: { id: ORG, name: 'alice', role: 'admin' }, expires: 1800000000,
};
const MEMBER = {
  user_id: '01J0000000000000000000USR2', username: 'bob',
  memberships: [{ id: ORG, name: 'alice', role: 'member' }],
  org: { id: ORG, name: 'alice', role: 'member' }, expires: 1800000000,
};

const BOARD = {
  board: { key: `${ORG}/${ORG}/rpi-1/dk-3`, org: ORG, node: `${ORG}/rpi-1`, name: 'dk-3' },
  node: `${ORG}/rpi-1`,
  chip: 'nRF52840_xxAA',
  model: 'nrf52840dk',
  tags: ['lab', 'nrf'],
  exclusive: true,
  power: 'uhubctl',
  availability: 'leased',
  holder: { key: 'user:01J0000000000000000000USR2', org: null, kind: 'user', id: '01J0000000000000000000USR2' },
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

test('login links every provider the deployment reports, returning to / by default', () => {
  const tree = login.render({ providers: ['github', 'oidc'] });
  const hrefs = findAll(tree, (n) => n.tag === 'a').map((n) => n.attrs.href);
  assert.deepEqual(hrefs, ['/auth/github/start?return_to=%2F', '/auth/oidc/start?return_to=%2F']);

  // A deep link survives sign-in.
  const deep = login.render({ providers: ['github'], returnTo: '/acme/keys' });
  assert.equal(find(deep, (n) => n.tag === 'a').attrs.href, '/auth/github/start?return_to=%2Facme%2Fkeys');

  // No in-page device flow and no signup form: forgs owns both.
  assert.equal(find(tree, (n) => n.tag === 'button' || n.tag === 'form' || n.tag === 'input'), null);
  assert.ok(!/device/i.test(textOf(tree)));

  const none = login.render({ providers: [] });
  assert.match(textOf(none), /coordinator user-token/);
});

test('login returns to the org page it was reached from, else /', () => {
  assert.equal(login.returnTo('/acme/keys'), '/acme/keys');
  assert.equal(login.returnTo('/acme/keys/'), '/acme/keys');
  for (const path of ['/', '/ui/', '/ui/devices', '/acme/nope', '/a.b/devices']) {
    assert.equal(login.returnTo(path), '/', path);
  }
});

test('a hostile provider name is encoded into one path segment and rendered as text', () => {
  const name = '../../x?y=<img src=x>';
  const tree = login.render({ providers: [name] });
  const link = find(tree, (n) => n.tag === 'a');
  assert.ok(link.attrs.href.startsWith('/auth/'));
  assert.equal(link.attrs.href.split('/').length, 4, link.attrs.href);
  assert.ok(!link.attrs.href.includes('<'));
  assert.ok(link.children.every((c) => typeof c === 'string'));
});

test('login loads providers from /auth/providers', async () => {
  const seen = [];
  const api = {
    get: async (path) => { seen.push(path); return { providers: ['github'] }; },
    describe: String,
  };
  const tree = await login.load({ api });
  assert.deepEqual(seen, ['/auth/providers']);
  assert.equal(find(tree, (n) => n.tag === 'a').attrs.href, '/auth/github/start?return_to=%2F');
});

test('devices renders the inventory and gates its actions by role', () => {
  const asHolder = devices.render({ boards: [BOARD], session: MEMBER });
  const text = textOf(asHolder);
  assert.match(text, /dk-3/);
  assert.match(text, /nRF52840_xxAA/);
  assert.match(text, /nrf52840dk/);
  assert.match(text, /user:01J0000000000000000000USR2/);
  assert.ok(labels(asHolder).includes('Release'), 'the holder sees Release');

  // A member who is not the holder does not; an admin does. Hiding is UX —
  // `tests/ui_authz.rs` is the half that matters.
  const asStranger = devices.render({ boards: [BOARD], session: { ...MEMBER, user_id: '01J0000000000000000000USR9' } });
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
    id: `${ORG}/rpi-1`, name: 'rpi-1', tags: ['lab'], adopt: 'declared',
    owner: ADMIN.user_id, last_seen: 1700000000, created_at: 1600000000, online: true, boards: ['dk-3'],
  };
  const tree = agents.render({ nodes: [node], session: ADMIN, editing: 'rpi-1' });
  const inputs = findAll(tree, (n) => n.tag === 'input' || n.tag === 'select').map((n) => n.attrs.name);
  assert.deepEqual(inputs.sort(), ['adopt', 'tags']);
  assert.match(textOf(tree), /cannot be changed/);
  assert.match(textOf(tree), /Renaming is not supported/);
});

// Agents counts *declared* boards (the `board` table) and Devices lists the
// *leasable* ones (the scheduler), so the two legitimately differ by boards
// whose probe is unplugged. The page has to say so, or the disagreement reads
// as the bug it used to be.
test('agents says its board count is the declared set, not the leasable one', () => {
  const node = {
    id: `${ORG}/rpi-1`, name: 'rpi-1', tags: [], adopt: 'declared',
    owner: ADMIN.user_id, last_seen: 1700000000, created_at: 1600000000, online: true, boards: ['dk-3'],
  };
  const text = textOf(agents.render({ nodes: [node], session: MEMBER }));
  assert.match(text, /declares/);
  assert.match(text, /unplugged/);
  assert.match(text, /Devices/);
});

test('approve renders the server warning verbatim, not a copy of the sentence', () => {
  // Deliberately not the production string: the page must render the *field*.
  const warning = 'SERVER-SUPPLIED WARNING TEXT, RENDERED VERBATIM.';
  const pending = {
    user_code: 'ABCD-1234', node_name: 'rpi-9', tags: ['lab'], adopt: 'declared',
    source_ip: '10.0.0.9', created_at: 1700000000, expires: 1700000900,
    org: TEAM, state: 'pending', warning,
  };
  const tree = approve.render({ pending, code: 'ABCD-1234', replace: false, session: ADMIN, targetOrg: TEAM });
  const text = textOf(tree);
  assert.ok(text.includes(warning), 'the warning field must be rendered');
  assert.match(text, /rpi-9/);
  assert.match(text, /10\.0\.0\.9/);
  // The target org is chosen before the confirm, and named in it.
  assert.ok(labels(tree).includes('Approve into ariel-os') && labels(tree).includes('Deny'));
  const picker = find(tree, (n) => n.tag === 'select' && n.attrs.name === 'org');
  assert.deepEqual(findAll(picker, (n) => n.tag === 'option').map((o) => o.attrs.value), [ORG, TEAM]);
  assert.equal(find(picker, (n) => n.tag === 'option' && n.attrs.selected).attrs.value, TEAM);

  // A server that sent no warning must produce a visibly empty box, never a
  // frontend copy of the sentence.
  const bare = approve.render({ pending: { ...pending, warning: undefined } });
  assert.ok(!textOf(bare).includes('ONLY if you started'), 'the sentence must not be hardcoded here');
});

test('approve names the collision before the confirm, not after', () => {
  const tree = approve.render({
    pending: {
      user_code: 'ABCD-1234', node_name: 'rpi-1', tags: [], adopt: 'declared',
      created_at: 1, expires: 2, state: 'pending', warning: 'w', org: ORG, collides_with: `${ORG}/rpi-1`,
    },
    session: ADMIN,
  });
  assert.match(textOf(tree), /alice already has a node called rpi-1/);
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
  assert.equal(access.granteeString('repo', 'kaspar030/probefleet'), 'repo:kaspar030/probefleet');
  assert.equal(access.granteeString('login', 'alice'), 'alice');
});

test('keys shows a minted key once, and says it will not be shown again', () => {
  const minted = {
    key: 'prfk1_SECRETVALUE', key_hash: 'a'.repeat(64), org: ORG,
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
    lines: [{ ts: 1700000000, action: 'lease.grant', board: 'dk-3', detail: 'user:01J0000000000000000000USR2' }],
  });
  const text = textOf(lines);
  assert.match(text, /lease\.grant/);
  assert.match(text, /no paging/);
});

const MEMBERS = [
  { user_id: ADMIN.user_id, username: 'alice', role: 'admin' },
  { user_id: MEMBER.user_id, username: 'bob', role: 'member' },
];

test('org gives an admin per-row role, remove and an add form', () => {
  const tree = org.render({ session: ADMIN, members: MEMBERS });
  const text = textOf(tree);
  assert.match(text, /alice/);
  assert.match(text, /bob/);
  const selects = findAll(tree, (n) => n.tag === 'select' && n.attrs.name === 'role');
  // One per row plus the add form's.
  assert.equal(selects.length, MEMBERS.length + 1);
  const bobRole = selects[1];
  assert.equal(find(bobRole, (n) => n.tag === 'option' && n.attrs.selected).attrs.value, 'member');
  assert.equal(labels(tree).filter((l) => l === 'Remove').length, MEMBERS.length);
  const add = find(tree, (n) => n.tag === 'form' && n.attrs.name === 'add-member');
  assert.ok(add, 'an admin sees the add-member form');
  assert.ok(find(add, (n) => n.tag === 'input' && n.attrs.name === 'username'));
  const addRole = find(add, (n) => n.tag === 'select' && n.attrs.name === 'role');
  assert.equal(find(addRole, (n) => n.tag === 'option' && n.attrs.selected).attrs.value, 'member');
});

test('org is read-only for a member and says why', () => {
  const tree = org.render({ session: MEMBER, members: MEMBERS });
  assert.equal(find(tree, (n) => n.tag === 'select'), null);
  assert.equal(find(tree, (n) => n.tag === 'form'), null);
  assert.ok(!labels(tree).includes('Remove'));
  assert.match(textOf(tree), /Only admins/);
  assert.match(textOf(tree), /admin/);
});

test('org shows the create form only when the session may create orgs', () => {
  const create = (tree) => find(tree, (n) => n.tag === 'form' && n.attrs.name === 'create-org');
  assert.equal(create(org.render({ session: { ...ADMIN, can_create_orgs: false }, members: MEMBERS })), null);
  assert.equal(create(org.render({ session: MEMBER, members: MEMBERS })), null);
  assert.ok(create(org.render({ session: { ...ADMIN, can_create_orgs: true }, members: MEMBERS })));
  // Independent of the role in the acting org.
  assert.ok(create(org.render({ session: { ...MEMBER, can_create_orgs: true }, members: MEMBERS })));
});

test('org shows rename and delete only to an admin of a team org', () => {
  const rename = (tree) => find(tree, (n) => n.tag === 'form' && n.attrs.name === 'rename-org');
  const del = (tree) => find(tree, (n) => n.tag === 'button' && n.attrs.name === 'delete-org');
  const team = { ...ADMIN, org: { id: ORG, name: 'acme', role: 'admin', personal: false } };
  const tree = org.render({ session: team, members: MEMBERS });
  assert.ok(rename(tree));
  assert.equal(find(rename(tree), (n) => n.tag === 'input' && n.attrs.name === 'name').attrs.value, 'acme');
  assert.ok(del(tree));
  // A personal org follows the username.
  const personal = { ...ADMIN, org: { ...ADMIN.org, personal: true } };
  assert.equal(rename(org.render({ session: personal, members: MEMBERS })), null);
  assert.equal(del(org.render({ session: personal, members: MEMBERS })), null);
  // A member of a team org.
  const member = { ...MEMBER, org: { id: ORG, name: 'acme', role: 'member', personal: false } };
  assert.equal(rename(org.render({ session: member, members: MEMBERS })), null);
  assert.equal(del(org.render({ session: member, members: MEMBERS })), null);
});

test('every page renders an empty state without throwing', () => {
  assert.ok(textOf(devices.render({ boards: [], session: MEMBER })).length > 0);
  assert.ok(textOf(agents.render({ nodes: [], session: MEMBER })).length > 0);
  assert.ok(textOf(approve.render({ pending: null })).length > 0);
  assert.ok(textOf(access.render({ grants: [], limits: null, session: ADMIN, form: {} })).length > 0);
  assert.ok(textOf(keys.render({ keys: [], limits: null, session: MEMBER, form: { purpose: 'node', tags: '', ttl_secs: 1, multi_use: false } })).length > 0);
  assert.ok(textOf(audit.render({ lines: [], session: ADMIN })).length > 0);
  assert.ok(textOf(login.render({ providers: null })).length > 0);
  assert.ok(textOf(org.render({ members: [], session: MEMBER })).length > 0);
  assert.ok(textOf(org.render({ members: null, session: null })).length > 0);
});
