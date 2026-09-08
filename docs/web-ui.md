# probe-rs-fleet — coordinator web UI and browser-facing HTTP API

Status: **implemented; phases 1–4 shipped.** This document fixes the shape of
a browser surface for the coordinator: how a browser authenticates, what the
JSON API looks like, who may call each endpoint, how the assets are served, and
what the first version deliberately does not do. It is written in the register
of `docs/architecture.md` — decisions *with their costs*, accepted risks
recorded rather than fixed, and explicit "please do not 'fix' this" notes where
a future reader would otherwise undo something deliberate.

The implementation lives in `crates/fleet-coordinator/src/browser_auth.rs`
(cookies, CSRF, the two login flows), `src/api.rs` (the `/api/v1` handlers),
`src/assets.rs` (the asset routes) and `web/` (the UI itself). Where this
document and the code disagree, the code is the fact and this document is the
bug; the sections below were amended as each phase landed rather than left as
the older plan.

**It reverses a recorded decision.** See [D1](#d1-browser-identity) — the
reversal is named there, with the file and section it reverses, because a silent
contradiction is the one outcome that would make this tree's documentation
untrustworthy.

Read `docs/architecture.md` §3.5 (routes, reverse proxy), §6.1 (identity model),
§6.2 (bearer tokens), §6.4 (bootstrapping, device flow), §6.5 (authorization)
first. This document assumes them and does not restate them.

---

## 1. What existed before this shipped

The starting point this design reacted to, kept because [D1](#d1-browser-identity)'s
recorded reversal is only legible against it. Every management operation was
CLI-only:

| what | before |
|---|---|
| inventory, leases, logs | `ctl list` / `ctl who` / `ctl logs` |
| board actions | `ctl lease` / `ctl release` / `ctl power-cycle` / `ctl delegate` |
| sharing | `grant <subject> …` / `grant list` / `grant revoke` |
| credentials | `auth-key create` / `auth-key list` / `auth-key revoke` |
| enrollment | `share`, `node up`, `node approve <code>` |

The only browser surface the coordinator had was `GET /node/approve`
(`crates/fleet-coordinator/src/http.rs`, `NODE_APPROVE_PAGE`): a static,
reflects-nothing page that tells you which command to run. It is still there and
still informational (see [§7](#7-changes-required-in-existing-files)), but `/ui`
and the `/api/v1` surface now sit alongside it. Users had asked for a web UI
where they could see their devices and agents, approve machines, and hand out
access. This document is the design for that; the code it produced is the
`browser_auth.rs` / `api.rs` / `assets.rs` / `web/` set named in the preamble.

---

## 2. Decisions

### D1. Browser identity

**Decided: GitHub authorization-code flow (PKCE + `state`) as the preferred
browser login, with an in-page device-code fallback; the session is carried by
an `HttpOnly` cookie holding the *existing* `prfs1_` session token.**

- New route `GET /auth/github/start` → 302 to GitHub's authorize endpoint;
  `GET /auth/github/callback` exchanges the code and mints a session through the
  same `mint_session_for_user` path `login` uses.
- The CLI's device flow (`POST /auth/device/{start,poll}`) is **unchanged**. No
  deployed CLI, agent or sidecar behaviour moves.
- **Fallback**: a deployment that has not registered a callback URL still gets a
  working, uglier browser login — the page shows a device code and a link to
  github.com, exactly as `login --headless` does. See
  [§3 Session](#session) for its two routes and why they exist rather than the
  page calling `/auth/device/*` directly.
- The session carrier is the **`session` table row** that already exists
  (`crates/fleet-coordinator/migrations/0001_init.sql`), delivered as
  `Set-Cookie: prfs_session=<prfs1_…>; HttpOnly; Secure; SameSite=Lax; Path=/`.
  Revocation stays "a row delete" (§6.2). The cookie is **a second carrier of
  the same credential, not a second credential kind**: `fleet_auth::authenticate`
  resolves it byte-for-byte as it resolves the `Authorization` header today.

**The reversal, stated loudly.** Architecture §6.4 says "No callback origin is
involved … there is no callback URL to fill in", §4.2 says node approval is a
CLI verb *because* "a page served by the coordinator cannot know who is looking
at it", and the module documentation of
`crates/fleet-coordinator/src/http.rs` says in as many words:

> approving from a browser would mean adding an OAuth redirect flow and cookies
> to the coordinator … Please do not "fix" it by bolting a session onto the
> coordinator.

That instruction was **correct for a coordinator with no web UI**, and it is
what this document changes. The cost is exactly the one it named: one
per-deployment setup step — registering `<public_url>/auth/github/callback` in
the OAuth app — which the device flow did not need. `[github]` stays optional,
and a deployment that skips the registration falls back to the device flow, so
the step is a nicety rather than a new requirement.

Those three passages must be amended when the implementation lands. That
amendment is **a follow-up task's job, not this document's**; until it happens,
this file is the newer decision and they are the older one.

**The seam this uses already exists, by design.** `http.rs::decide_pending_node`
takes an *already-resolved* subject precisely so a cookie-authenticated handler
can resolve its subject its own way and call the same function. No schema
change, no second binding site. The web approval flow in
[phase 2](#6-phased-plan) is that commitment being cashed in.

**`redirect_uri` is derived from `public_url`, never from the request.** Not
`Host`, not `X-Forwarded-Host`. The coordinator runs behind a reverse proxy
(§3.5) and does not see its own public name; a Host-derived callback is a
host-header-injection route to an attacker-controlled OAuth redirect. The
callback path is fixed (`/auth/github/callback`) and the origin is configuration.

**`Secure` is unconditional.** The example config's `public_url` is
`http://127.0.0.1:7000`, and that still works: browsers treat
`http://localhost` and `http://127.0.0.1` as secure contexts, so a `Secure`
cookie is set and returned there. Any *other* plain-HTTP deployment is
**unsupported for the UI** rather than silently downgraded to a non-`Secure`
cookie. Please do not make `Secure` conditional on the scheme — that is the
obvious "fix" and it would hand every session to anyone on the path.

**Session lifetime: no silent refresh in v1.** `session_ttl_secs` defaults to
12h. The cookie's `Max-Age` tracks the row's `expires`, so the browser never
holds a cookie the database has already forgotten, and a `401` from any
`/api/v1/*` endpoint means "log in again" — the UI bounces to
`/auth/github/start`. `POST /auth/token` with `grant_type: refresh` stays a
**CLI-only** path: a cookie-driven refresh endpoint would be a CSRF target that
mints a fresh credential, in exchange for saving a redirect the user notices
twice a day.

**CSRF.** Two independent controls:

1. A **double-submit token**: `prfs_csrf` = `HMAC(k, session_token_hash)`, set as
   a non-`HttpOnly` cookie and echoed by the UI in an `X-Fleet-Csrf` header on
   every mutating call. Derived, so there is **no schema change** and no
   server-side CSRF table.
2. The header must be **present** on every mutating call at all. A custom header
   cannot be sent cross-origin without a preflight, and the coordinator emits no
   CORS headers anywhere, so the preflight fails. The UI is same-origin by
   construction.

`k` is derived from the coordinator's existing ed25519 signing seed
(`signing.seed`, `config::SigningKeySource`) with a domain-separation label —
**not** a per-process random. A per-process key would log every open tab out on
every restart, and the first implementer to hit that would "fix" it by
persisting a second secret. Rotating the signing seed invalidates open tabs'
CSRF tokens, which is correct and is already true of every capability token.

**Bearer-from-JS was rejected.** `Authorization: Bearer` from JavaScript needs
no CSRF machinery, which is its whole appeal — but a token readable by JS is a
token exfiltrable by one XSS, and this credential can power-cycle real hardware.
`HttpOnly` plus the CSRF pair is the trade this design takes. See
[§5 Threat notes](#5-threat-notes).

**Blast radius of the cookie is exactly `/api/v1/*`.** Cookie authentication is
accepted there and nowhere else. It is rejected on `/agent`, `/client` and
`/delegate` — a browser must never drive a control-plane WebSocket by ambient
authority, and `/delegate` mints no `Subject` at all — and also on
`/auth/token` and `/auth/keys`, the existing CLI JSON endpoints, which keep
requiring an explicit bearer.

### D2. API shape

**Decided: JSON over HTTP at `/api/v1/…`, sharing the coordinator's handlers.**

Not the postcard `/client` WebSocket from JavaScript. That would need a second
postcard codec in the browser, and long-lived WebSocket state buys nothing for
request/response management verbs. The data plane is not going to the browser
(D4), so the one thing the WebSocket is good at is not needed.

**The no-drift guarantee is structural.** Each endpoint calls the *same*
`Coordinator` method `handle_sidecar_message` dispatches to — `list_boards`,
`who`, `logs`, `operator_power_cycle`, `grant_create`, `grant_list`,
`grant_revoke`, `release_lease` — and those methods hold the authorization
checks. HTTP becomes a second **encoding**, not a second authorization
implementation.

> An endpoint that re-implements a check instead of calling the shared method is
> the exact failure mode this design exists to prevent. If a handler is
> tempting to write "just this once" against `OrgDb` directly, the check has to
> move into a `Coordinator` method that both surfaces call.

Response bodies are the existing `fleet-proto::admin` DTOs — `BoardSummary`,
`LeaseHolderSummary`, `LogLine`, `GrantSummary` — serialized as JSON; they
already derive `Serialize`. One wrinkle to check at implementation time: those
types are shaped for postcard, and any that do not serialize to pleasant JSON
(newtype ids, `BoardRef`'s three parts) get a thin view struct **in the
coordinator**, never a divergent field set in `fleet-proto`.

**The honest cost.** Today's operator methods on `Coordinator` are private, and
several verbs the UI needs **have no wire verb at all**: node tags /
adopt-policy / delete, member list (node *list* has since gained one:
`SidecarToCoord::ListNodes`, added for `ctl nodes` and sharing this document's
`list_nodes_core`). Those are
new `Coordinator` methods plus new `state.rs` / `OrgDb` queries — real
implementation work in the follow-up tasks, not plumbing. Every new query goes
through `OrgDb` so the tenancy fence holds by construction (`audit_log.org_id`
is `NOT NULL REFERENCES org(id)` and the table is reachable only through
`OrgDb`; that combination is what makes "no code path can forget the org check"
true).

### D3. Frontend stack and asset serving

**Decided: hand-written HTML plus plain ES modules using `fetch`, embedded in
the binary. No npm, no bundler, no TypeScript compile, no build step at all.**

- Source lives in `crates/fleet-coordinator/web/` — not a `web/` at the repo
  root, not a `fleet-web` crate. The assets are part of the binary that serves
  them.
- Embedded with `include_dir!`, served under `GET /ui/*`. The coordinator stays
  a single cross-compilable binary behind a reverse proxy (§3.5).
- **A `cargo build` with no node/npm installed keeps working — structurally, not
  as a fallback.** There is no build script, no generated artifact, nothing to
  keep in sync, so there is no state in which the check could fail. That is the
  reason this stack was chosen over a nicer one.
- Strict CSP on every UI response:
  `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. No
  inline script, no CDN.

**What shipped, and the four things the implementation had to decide** (phase 2;
`crates/fleet-coordinator/src/assets.rs` carries the same notes at the call
site):

1. **One tree hash, not per-file hashes.** Nothing hashes filenames at build
   time, because there is no build. Assets are served under
   `/ui/a/{tree-hash}/{path}` — SHA-256 over every embedded file's path and
   bytes in sorted order, first 16 hex characters — with a one-year `immutable`
   `Cache-Control`, and `index.html`'s `__ASSETS__` token is rendered once into
   that prefix. Per-file hashes are the obvious "improvement" and they are
   wrong: a module at `/ui/a/H/app.mjs` doing `import './api.mjs'` resolves to
   `/ui/a/H/api.mjs`, so a per-file scheme would serve one file under another's
   hash and break its invalidation silently. The hash segment is a **cache key,
   not a check** — a stale hash still serves current bytes, because 404ing it
   would break an open page across a restart that changed the assets.
2. **No global `Router::fallback`, anywhere.** Every catch-all is scoped under
   `/ui/`, and the client-side routes are listed explicitly. That is what makes
   "the shell cannot swallow `/api/*`, `/agent`, `/client`, `/delegate`,
   `/healthz` or `/node/approve`" a property of the router's *shape* rather than
   of a test that samples it, and it is why an unknown top-level path is an
   empty 404. The instinct when a new client-side route 404s is to add
   `.fallback(shell)`; the answer is to add the page to `PAGES` in
   `src/assets.rs`, from which the router derives both the bare `/ui/<page>` and
   the trailing-slash `/ui/<page>/` spelling. Both are registered because the
   client router strips a trailing slash, so serving only the bare form made a
   *cold* load of `/ui/devices/` a 404 that navigation within the shell never
   reproduced.
3. **Every frontend module is `.mjs`, and there is no `package.json`.** A `.js`
   module is resolved as CommonJS by node < 22.7 and by any node whose upward
   walk finds a package scope it dislikes — including an unparseable
   `package.json` anywhere above the checkout, which is outside this repository's
   control. `.mjs` is unambiguous on every version with no configuration, so the
   JS tests need no file whose only job is to placate a resolver, in a tree whose
   headline decision is "no npm, no bundler".
4. **Text safety is structural, not a review habit.** `web/dom.mjs` is the only
   place anything enters the DOM: `textContent` only, plus an allowlist of
   settable attributes and a `/`-or-`#` check on `href` (the CSP is the primary
   control there; the allowlist is the second). Handlers travel in a vnode `on`
   channel and never as an `on*=` attribute, and nothing carries a `style=`
   attribute — under `script-src 'self'` / `style-src 'self'` with no
   `unsafe-inline`, both are dead code. `tests/ui_assets.rs` lints the embedded
   tree for all of it, plus for any client-side storage API and any absolute-URL
   import.

**Cost, recorded:** no type checking, and hand-rolled DOM code. If the UI
outgrows it, adding a bundled TypeScript build later does not move the API — the
seam is the JSON contract, and the endpoints in §3 do not change.

**CI.** The repository has **no `.github/workflows/` at all** today, and
`docs/ci-github-actions.md` is the *consumer* workload-identity guide, not a
build-pipeline document. So "how the frontend is built in CI" has nowhere to
land — and with a zero-build frontend there is nothing to add. This is recorded
rather than silently omitted, and phase 2 deliberately did **not** touch that
file. If D3 is ever revisited, the revisit has to bring
a pipeline with it: a bundled frontend means a build step whose output must be
in the binary, which means either a checked-in artifact (drifts) or a `cargo
build` that needs node (breaks the cross-compilation story in
`docs/cross-compiling.md`).

The one wrinkle phase 2 *did* add: the frontend's unit tests
(`crates/fleet-coordinator/web-tests/*.test.mjs`, node's built-in runner, zero
npm dependencies) want `node` on `PATH`. `tests/ui_js.rs` runs them when it is
there and prints a loud skip when it is not, so neither `cargo build` nor `cargo
test` requires a JavaScript toolchain — at the honest cost that on a machine
without node that coverage silently disappears. **A pipeline that ever exists
should install node**: one line, no npm, no network. Note also that
`include_dir!` embeds the *whole* subtree, which is why those tests live in
`web-tests/` beside `web/` rather than inside it — anything under `web/` ships in
the binary and is publicly served.

### D4. v1 scope fence

**In:** read-only inventory (boards, leases, nodes, grants, auth keys, audit
log), plus the management verbs — power-cycle, release someone else's lease as
admin, node tags / adopt-policy / delete (**not** rename; see §3), pending-node
approval, grant
create / list / revoke, auth-key mint / list / revoke.

**Out**, each with its reason:

- **No lease acquisition from the browser.** Worth arguing rather than
  asserting: a lease taken in a browser has no sidecar to use it. The lease is
  only useful to a machine running `probe-rs`, so a browser button would be
  "reserve this board for me", which is a real feature — and it immediately wants
  a holding/extending/expiring UI (heartbeats come from the sidecar; a browser
  tab that closes leaves a board held until TTL), a way to hand the lease to a
  sidecar, and a story for what a queued request looks like in a page that is
  not polling. Phase 1 should not grow that. Deliberately unscheduled, not
  refused forever.
- **No data-plane or board console.** Nothing relays probe-rs traffic to a
  browser. That would mean a second relay ingress with a browser-shaped
  credential.
- **No `delegate`.** It hands out a capability token; see the threat notes.
- **No org creation and no invites.** The personal org is auto-created on first
  login (§6.1); membership is **read-only** in v1.
- **No capability token ever reaches the browser.** Not `LeaseGrant::token`, not
  `ChannelOpened::token`, not the `/delegate` bearer. This should be enforced by
  a test over the API response types, not by review vigilance.
- **Auth-key minting IS in scope**, with a shown-once panel matching the CLI's
  behaviour. This is the one place the web surface creates a long-lived bearer
  secret, and it is a deliberate, accepted cost: the alternative is a UI in
  which the most-asked-for enrollment path is the one thing you must leave the
  browser for.

---

## 3. Endpoint table

Everything under `/api/v1/*` accepts the session cookie (D1) **or** an
`Authorization: Bearer <session>` header, resolves to a `Subject` through the
same construction site as today, and returns `application/json`. Mutating calls
require the `X-Fleet-Csrf` header. Errors keep the existing shape:
`{"error":"<code>"}`, coarse by design (§4).

Two path-shape decisions, both forced by the id grammar:

- **A `BoardRef` has four slash-separated segments** (`org/org/node/name` —
  `state.rs::node_id_for` builds `NodeId("{org}/{name}")`), so boards are never
  addressed in a path. Board-targeting endpoints take the node-local name (or a
  qualified name, per §6.5's `BoardRef::answers_to` grammar) **in the body**,
  exactly as the wire verbs do, and the coordinator resolves it within the
  caller's access.
- **Node ids contain a slash** for the same reason, so node endpoints address a
  node by its node-local `name`, which is `UNIQUE (org_id, name)`, resolved
  within the caller's org.

### Session

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/auth/methods` | — | `{"login":"authorization_code"\|"device"\|"none"}` | config only | anyone (unauthenticated; reveals only which login this deployment offers) |
| `GET /auth/github/start` | — | `302` to GitHub; PKCE verifier + `state` in a short-lived `HttpOnly` cookie | new | anyone |
| `GET /auth/github/callback?code&state` | — | `302 /ui`, `Set-Cookie: prfs_session`, `Set-Cookie: prfs_csrf` | `mint_session_for_user` | anyone with a valid `state` |
| `POST /api/v1/session/device/start` | `{}` | `{"user_code","verification_uri","interval","expires_in"}` — **no `device_code` in the body**; it is stashed in a short-lived `HttpOnly` cookie | `http::auth_device_start` (as `/auth/device/start`) | anyone |
| `POST /api/v1/session/device/poll` | `{}` | `{"status":"pending"\|"ok"}`; on `ok`, `Set-Cookie` as above. **Never returns a token.** | `http::auth_device_poll` + `mint_session_for_user` | anyone holding the device cookie |
| `GET /api/v1/session` | — | `{"user","login","org","org_slug","role","expires"}` | `db.role_of` | any session |
| `POST /api/v1/session/logout` | `{}` | `204`, cookies cleared | `Db::delete_session` | any session |

The device fallback deliberately does **not** have the page call
`/auth/device/{start,poll}` directly: those return the `device_code` and then the
session token *in the response body*, i.e. to JavaScript, which is precisely the
exposure D1 rejects. The two `/api/v1/session/device/*` routes are the same
stateless brokering with both secrets moved into `HttpOnly` cookies. No new
table; the device code still round-trips through the client, so a coordinator
restart mid-login is still survivable. The `http::` names above are the
coordinator handlers; the CLI calls the same two routes through
`fleet_auth::http_client::{device_start, device_poll}`.

Which login the page offers is chosen by `GET /api/v1/auth/methods`, driven by
one config field (see [§7](#7-changes-required-in-existing-files)) — not by a
bundle, since D3 means there is no build to branch in.

### Orgs and membership (read-only in v1)

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/org` | — | `{"id","slug","kind","role"}` | `Db::org_slug`, `Db::role_of` | member |
| `GET /api/v1/org/members` | — | `[{"user_id","login","role"}]` | **new** `OrgDb::list_members` | member |

### Nodes

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/nodes` | — | `[{"id","name","tags","adopt","owner","last_seen","online","boards"}]` | **new** `Coordinator::list_nodes` → **new** `OrgDb::list_nodes` (+ `NodeRegistry` for `online`) | member |
| `PATCH /api/v1/nodes/{name}` | `{"tags"?,"adopt"?}` | the updated node row | `Coordinator::update_node_core` → `OrgDb::update_node` | node owner, or admin |
| `DELETE /api/v1/nodes/{name}` | — | `204` | `Coordinator::delete_node_core` → lease teardown + scheduler removal + `OrgDb::delete_node` + close the live connection | node owner, or admin |
| `POST /api/v1/nodes/pending/{code}` | `{"decision":"inspect"\|"approve"\|"deny","replace":false}` | `NodeApprovalResponse` + a `warning` field | `http::decide_pending_node` (**unchanged**) | member |

`boards` in a node row is the **declared** set, not the leasable one: the names
in the coordinator's `board` table, i.e. every board the machine's latest
inventory report carries, including ones whose probe is currently unplugged. A
board the node stops declaring (renamed, or deleted from `boards.toml`) is
pruned on its next report. `GET /api/v1/boards` reads the *scheduler* instead —
what can be leased right now — so the Agents count is legitimately ≥ the Devices
list, differing exactly by the declared-but-offline boards. The field carries no
per-board presence; adding it would widen this payload for a display nicety.

There is deliberately **no** `GET /api/v1/nodes/pending`. An earlier revision of
this table had one; it is dropped, for the reason §4 now records:
`pending_node.org_id` is `NULL` until an approval binds it, so there is no
attribution to filter a listing on, and a member-visible list of live codes
would be exactly the cross-tenant index §4 forbids. Approval stays code-driven.
Adding an org column to `pending_node` is a separate design question, not
something to smuggle in alongside a listing.

`DELETE` is a revocation, not a tidy-up: deleting the `node` row invalidates its
token (§4.2), so the implementation must also tear down that node's live leases
and drop its connection, or the machine keeps relaying until its lease TTL runs
out — the same trap `grant_revoke` already solves by going through the whole
release path. It also has to remove the node's `board` rows: `board.node_id
REFERENCES node(id)` is enforced, so a bare `DELETE FROM node` fails for any
node that has ever reported a board. And it must *close* the node's
control-plane socket, not merely drop its registry entry: the connection task
holds its own sender, so removing the entry makes the node unroutable while the
socket lives on — an operator who deleted a node would still have the machine
attached. `NodeRegistry::remove_and_close` is the revocation-side call.

**`PATCH` does not rename, and says so.** The node id is `{org}/{name}`; it is a
primary key referenced by `board.node_id` under `PRAGMA foreign_keys = ON`, it
is carried (with *no* foreign key, so nothing would catch a stale one) in
`leases.node_id`, and it is embedded in every live `BoardRef` in the in-memory
scheduler. A rename would therefore have to cascade through three places, one
of which the database cannot help with. **Refusing is the v1 answer** — the
recorded decision this table asked the implementation to make. `PATCH` offers
`tags` and `adopt` only, and a `name` field in the body is a `400
invalid_request`, never a silent no-op: an operator must not be left believing a
rename happened while their scripts, their `boards.toml` and the audit log all
disagree. Renaming, if it is ever wanted, is "delete and re-enroll" or a
deliberate follow-up that moves all three.

### Boards and leases

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/boards` | — | `[BoardSummary]` | `Coordinator::list_boards_core` | anyone with non-empty `Access` |
| `POST /api/v1/boards/power-cycle` | `{"board":"<name or qualified>"}` | `{"board":"…"}` | `Coordinator::operator_power_cycle_core` | `board_access` + `AllowedOp::PowerCycle` for a grantee |
| `GET /api/v1/leases` | — | `[LeaseHolderSummary]` | `Coordinator::who_core` | anyone with non-empty `Access` |
| `DELETE /api/v1/leases/{lease_id}` | — | `{"lease":N}` | `Coordinator::release_lease_core` | lease holder, or org admin |

There is no `POST /api/v1/leases` (D4).

A `lease_id` is a `u64`, which is why it is the one identifier on this surface
that may live in a path at all: unlike a `BoardRef` or a node id it contains no
slash. A non-numeric segment is a `400 invalid_request` rather than a `404` — it
is a malformed request, not an answer about whether a lease exists. "Org admin"
means the **board org's** admin, so reclaiming your own hardware from somebody
you shared it with works; `authz::require_lease_control` already says so, and a
stranger gets the answer they would get for a lease that does not exist.

### Grants

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/grants` | — | `[GrantSummary]` | `Coordinator::grant_list_core` | member |
| `GET /api/v1/grants/limits` | — | `{"max_ttl_secs","expires_optional","now","ops":[…],"min_revoke_prefix","auth_key_max_ttl_secs"}` | config only | member |
| `POST /api/v1/grants` | `{"subject","selector","ops":[…],"expires":N}` | `GrantSummary` | `Coordinator::grant_create_core` | **admin** |
| `DELETE /api/v1/grants/{id_prefix}` | — | `{"revoked":["…"]}` | `Coordinator::grant_revoke_core` | grant creator, or admin |

Note the deliberate divergence from auth keys: grant **create** is admin-only
while grant **list** needs only membership. An auth key cannot exceed the
caller's own org (it enrolls a node *into* it); a grant points outward, handing
the org's hardware to somebody who is not in it at all.

`selector` is the **canonical selector string** and is canonicalised
server-side: `id=<name>` (one board), `board=<model>` (any board of that board
type), `chip=<c>`, `tag=<t>`, and `a && b` conjunctions of tags, parsed by
`fleet_proto::lease::parse_constraint` — where a bare word is always a tag —
and stored
as `Constraint`'s `Display`. A grant's meaning must never depend on which
surface wrote it, so the UI sends the same string a CLI would and does **not**
build a structured selector of its own. An empty expression is refused (an empty
tag set matches every board).

`ops` are `AllowedOp` labels. §6.5's `--ops` table applies unchanged, including
the honest part: `attach` and `gdb` are enforced by the agent, `power-cycle` by
the coordinator, and `flash` / `erase` / `reset` are **recorded intent, not
enforcement**. The UI must say so where ops are picked, or it will read as a
permission system it is not. A data-plane op implies `attach`, and that
implication must be shown, as the CLI shows it.

**That op table ships as data, not as prose.** `GET /api/v1/grants/limits`
returns, per op, its label, `enforced_by` (`agent` / `coordinator` / `nobody`)
and `implies_attach`, read from `AllowedOp::is_enforced` and
`AllowedOp::needs_data_channel`. A frontend that re-derived the table from this
document would drift from the enum the first time an op moved.

`expires` is **required and capped on both ends**: it must be in the future and
no more than `Coordinator::MAX_GRANT_TTL_SECS` (365 days) away — `core.rs`
refuses `expires <= now` as well as an over-long TTL, and refuses an absent one
outright. Both bounds, plus the server's own `now`, come back from
`GET /api/v1/grants/limits`, so the date picker constrains itself from the
contract rather than from a hardcoded `365` that goes stale silently (and from
the *coordinator's* clock, not the browser's — that difference is exactly what
turns "one minute from now" into a `400`).

### Auth keys

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/auth-keys` | — | `AuthKeyList` (hashes only) | `http::list_auth_keys` (**unchanged**) | member |
| `POST /api/v1/auth-keys` | `{"tags":[…],"ttl_secs":N,"multi_use":false,"purpose":"node"\|"ci","ops":[…],"subject_name":"builder"\|null}` | `AuthKeyCreated` — **the only time the secret exists** | `http::create_auth_key` (**unchanged**) | member |
| `DELETE /api/v1/auth-keys/{hash_prefix}` | — | `AuthKeyRevoked` | `http::revoke_auth_key` (**unchanged**) | key creator, or admin |

`ttl_secs = 0` is a `400` and the TTL is capped at 30 days
(`MAX_API_AUTH_KEY_TTL_SECS`), exactly as on `POST /auth/keys` — the same
function is called, so `purpose` outside `node` / `ci` is a `400`, a `ci` key
with no tags is a `400`, and revoking a `ci` key cascades into the grant its
redemption synthesised. The prefix must be at least 8 hex characters. Both
numbers are also reported by `GET /api/v1/grants/limits`. The UI shows the key
once, in a panel that says it will not be shown again, and never stores it
anywhere.

`subject_name` names the **identity** a `ci` key speaks as — architecture §6.7's
named auth-key identity, `<org>/workload:agent:<name>`, which survives rotating
the key. It is optional; absent (or `null`) keeps the historical hash-derived
subject, so an existing UI needs no change. Three things are `400`, and all
three are that same shared function's rules:

- a `subject_name` alongside `"purpose":"node"` — a node key confers no subject
  for a name to attach to, so it is refused rather than stored inert;
- a name outside `[a-z0-9._-]`, not starting with a letter or digit, empty, or
  longer than 64 characters. Names are **lowercased** on the way in, so the
  echoed `AuthKeyCreated.subject_name` may differ from what was sent — display
  the echo, not the input;
- `"purpose":"agent"`. That spelling is **CLI-only sugar** for `ci` and is not a
  wire value; the allowlist here is still exactly `node` / `ci`.

`AuthKeyCreated` and each `AuthKeyInfo` echo `subject_name`, so a listing can
show which keys share an identity. That is worth surfacing rather than hiding:
keys sharing a name share **one grant**, so revoking any one of them tears that
grant down and releases every live lease under the identity — including another
key's runner. A surviving key with the same name re-creates the grant on its
next redemption.

`POST /api/v1/auth-keys` is the **one** place this surface returns a long-lived
bearer secret, and it is not a counter-example to "no capability token ever
reaches the browser" (§5, D4): an auth key is org-scoped, expiring, listable,
revocable and confers only the right to *enroll*, where a capability token is
offline-verifiable, unrevokable short of tearing down its lease, and confers
control of a leased board.

### Audit log

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/audit?board=<name>` | — | `[LogLine]`, newest first, **at most 200** | `Coordinator::logs_core` | **admin** |

**v1 has no paging and no filtering beyond `board`.** `logs()` calls
`OrgDb::recent_audit` with a hardcoded limit of 200 and this endpoint keeps that
number rather than inventing a cursor API for one surface. Stated here so the
first reviewer of the UI does not read "audit log" and expect one.

### Assets

| Method + path | Response |
|---|---|
| `GET /` , `GET /ui` | `302` → `/ui/`, so relative asset URLs resolve against the canonical path |
| `GET /ui/` and each client-side route, with or without a trailing slash (`/ui/devices`, `/ui/devices/`, … for `devices`, `agents`, `approve`, `access`, `keys`, `audit`) | the shell, `Cache-Control: no-cache` |
| `GET /ui/a/{tree-hash}/{path}` | one embedded asset, `public, max-age=31536000, immutable` |
| `GET /node/approve` | unchanged URL, unchanged reflection-free page, plus one static link to `/ui/approve` |

All of them carry the CSP and hardening headers above, authenticate nothing and
set no cookies — the shell has to load before a session exists, because login is
a page inside it. A `/ui/` path whose last segment has an extension is a `404`
rather than the shell, which is what makes a typo'd `import` surface as a broken
import instead of as HTML parsed as JavaScript.

`/node/approve` keeps its path because deployed agents print it. The page's
"reflects nothing" property survived phase 2 intact: it grew a static paragraph
linking to `/ui/approve`, where the same JSON endpoint is driven from a real
form, and it still reads no query parameter and renders byte-identically
whatever the query string. It did **not** grow the form itself — that would put
attacker-supplied text on an unauthenticated page.

---

## 4. Authorization on the new surface

**Deny by default.** Every endpoint resolves to a `Subject` and is checked
against the *target object's* org through the existing evaluator —
`authz::require_role`, `authz::board_access`, `authz::require_lease_control`,
`fleet_core::access::Access`. Nothing on this surface evaluates access itself.

| Endpoint group | Rule | Where it already lives |
|---|---|---|
| boards list, leases list | non-empty `Access` (own-org membership, or a live grant) | `authz::board_access` |
| power-cycle | `Access` + `AllowedOp::PowerCycle` for a grantee | `Coordinator::operator_power_cycle_core` |
| lease release | **holder, or the board org's admin** | `authz::require_lease_control` |
| grant create | **admin** | `require_role(Admin)` |
| grant list | membership | `require_role(Member)` |
| grant revoke | **creator, or admin** | `Coordinator::grant_revoke_core` |
| auth-key mint / list | membership | `http::require_membership_for_auth_keys` |
| auth-key revoke | **creator, or admin** | `http::revoke_auth_key` |
| audit log | **admin** | `Coordinator::logs_core` (+ `OrgDb` scoping, a second independent fence) |
| org / member list | membership | new, `require_role(Member)` |
| pending-node approve / deny | membership | §6.4, `decide_pending_node` (there is no listing; see §3/§4) |
| node list | membership | new |
| node tags / adopt / delete | **owner (`node.owner_user_id`), or admin** | **new policy, fixed here** (rename is refused; see §3) |

Three notes on that table.

**Node mutation is new policy.** No CLI verb exists for renaming or deleting a
node, so there is no existing rule to match. Owner-or-admin mirrors
`node.owner_user_id` and the lease-ownership rule of §6.5. Its one sharp edge:
a node enrolled with an auth key or from a shell has `owner_user_id = NULL`, so
it is **admin-only** — deliberate, and the same shape as auth keys with no
recorded creator.

**Pending-node approval inherits §6.4's cross-tenant code-enumeration risk
unchanged.** An authenticated member who guesses a `user_code` can inspect and
approve into their own org a registration somebody in another org started. The
browser does not make this worse — it is the same handler, the same ~40 bits
behind a 15-minute TTL, the same audit row, and the same "the enrolling machine
prints which org it landed in" control that lets the victim notice.

What the browser must not do is make it *better-indexed*, and that is why
**there is no pending-registration listing**. `pending_node.org_id` is `NULL`
until an approval binds it (`migrations/0005_pending_node.sql`) and
`Db::live_pending_codes` is org-blind, so a listing has no attribution to filter
on: it could only show *every* live code in the deployment. That is precisely
the cross-tenant index this section forbids, and it would strictly worsen the
accepted risk above — turning "guess ~40 bits" into "read the list". So `GET
/api/v1/nodes/pending` is dropped (see §3) and approval stays code-driven: you
approve an enrollment whose code somebody handed you, which is the ceremony the
CLI already implements.

Because nothing lists them, the human deciding has *only* what the `inspect`
response tells them, so the phishing warning the CLI prints must appear
verbatim in the form: *you cannot see this machine; approve only an enrollment
you started.* It ships as a server-sent `warning` field on the `inspect`
response (`api.rs`'s `APPROVAL_WARNING`, byte-identical to the CLI's sentence)
rather than as frontend copy, so a frontend that forgets to render it shows a
visibly empty box instead of silently dropping the mitigation.

**Errors stay coarse.** A cross-org object and a nonexistent one must be
indistinguishable (`AuthzError::lease_message`, `denied()`, the flat
`invalid_grant`), or the API becomes an org-enumeration oracle. This is easier
to get wrong in a JSON API than on the wire, because a REST-shaped handler
naturally wants to answer `404` for "no such node" and `403` for "not yours".
It must not.

---

## 5. Threat notes

**Bearer-token exposure in a browser.** A token readable by JavaScript is a
token exfiltrable by a single XSS, and can then be replayed from anywhere with
no cookie, no CSRF header and no same-origin constraint. That is why the session
is `HttpOnly` and why `Authorization: Bearer` from JS was rejected (D1). The
cost is the CSRF machinery, which is the trade taken.

**XSS blast radius.** A session cookie on this surface can power-cycle real
hardware, release someone's lease, delete a node, create a grant that hands the
org's boards to an outsider, and mint an auth key. That is what justifies the
strict CSP, no inline script, no CDN, and the shown-once auth-key panel. Every
piece of attacker-controlled text this UI renders — node names, tags,
`user_code`, grant subjects, audit details — is server-side charset-validated
(as §6.4 already requires) *and* inserted as text, never as HTML.

**No capability token ever reaches the browser.** A capability token is a
signed, offline-verifiable bearer credential that the coordinator cannot revoke
short of tearing down the lease (§6.5) — it is exactly the wrong thing to put
where an XSS can read it. So: no `delegate` endpoint, no lease acquisition, no
`ChannelOpened::token`, no `LeaseGrant::token`. Enforce it with a test over the
API's response types rather than by remembering.

The one long-lived secret this surface *does* return —
`POST /api/v1/auth-keys`'s `AuthKeyCreated.key` — is not one of these, and the
enforcing test knows the difference by name rather than by prefix class: an auth
key is org-scoped, expiring, listable, revocable (cascading into any grant it
synthesised) and confers only the right to enroll. D4 accepts it explicitly.

**CSRF, both options stated.** With `Authorization: Bearer` from JS there is no
CSRF at all — the credential is not ambient — but see the first note. With a
cookie, every authenticated endpoint is reachable by any page the user visits
unless something else stops it; `SameSite=Lax` stops cross-site *form* posts and
top-level `POST` navigations but is not a complete answer (it does not help
against a same-site subdomain, and its behaviour across browsers has moved
before). Hence both the double-submit token and the mandatory custom header, and
no CORS headers anywhere.

**Host-header injection at the callback.** Covered in D1: `redirect_uri` comes
from `public_url`. A `Host`-derived callback behind a proxy is an
attacker-chosen OAuth redirect, i.e. an account takeover.

**Inherited, not introduced.** The web surface adopts these existing accepted
risks unchanged, and adds no new mitigation for them:

- **No rate limiting anywhere in the coordinator.** `/auth/github/start` and the
  device fallback are as unauthenticated as `/auth/device/start` is today, with
  the same quota-exhaustion exposure and no credential exposure.
- **Device-flow remote phishing** (RFC 8628 §5.4), for the fallback login and,
  sharpened, for node approval (§6.4).
- **Unauthenticated `pending_node` growth**, capped by `max_pending_nodes`
  (default 256) and reclaimed by the TTL sweep.

Adding rate limiting is a coordinator-wide change and belongs in its own task,
not smuggled in with a UI.

---

## 6. Phased plan

All four phases have shipped. The API phases (1a–1c below, tracked as tasks
#3572/#3573/#3574) landed first, and the UI that consumes them landed as one
deliverable (#3540) once every endpoint it needed existed — which is the order
the fence below was designed to produce.

**Phase 1 — read-only inventory.** *Shipped.* Login (D1), `/ui`, boards + leases
+ nodes list, `GET /api/v1/session` / `org` / `org/members`, audit log for
admins. **No mutating endpoint at all**, so the cookie, CSP and CSRF machinery
shipped and got exercised before anything existed that could be abused through
them.

**Phase 2 — node management and pending approvals.** *Shipped.* `PATCH` /
`DELETE` on nodes and `POST /api/v1/nodes/pending/{code}` — the §4.2 commitment
cashed in, calling the existing `decide_pending_node`. (`/node/approve` growing
a real form behind the session is *not* part of it: the browser approves through
the JSON API, and that page stays informational and reflection-free.)

**Phase 3 — grants and auth keys.** *Shipped.* The admin-gated,
outward-pointing verbs, and the shown-once auth-key panel. Deliberately after
phase 2: these are the two surfaces where a mistake hands hardware to someone
else.

**Phase 4 — board actions.** *Shipped.* Power-cycle, and admin release of
someone else's lease.

**Deliberately unscheduled:** lease acquisition, delegation, board console, org
creation, invites and membership management.

---

## 7. Changes required in existing files

Named so follow-up tasks could be scoped precisely; all of them have now been
made. Retained as the record of what each phase was expected to touch — and, at
the bottom, of the one item that was deliberately *not* touched.

- **`crates/fleet-coordinator/src/http.rs`** — the new `/api/v1/*` and
  `/auth/github/*` routes; a cookie-aware sibling of `authenticate_request`
  (same `Subject` construction, one extra credential *carrier*, not a new
  credential *kind*), with the carrier allowlisted per route; the CSRF
  derivation and check. **The module doc's "please do not bolt a session onto
  the coordinator" paragraph must be rewritten, not quietly contradicted.**
  (`/node/approve` stays informational: the browser approves through
  `POST /api/v1/nodes/pending/{code}`, which calls the same
  `decide_pending_node` and shares its membership check.)
- **`crates/fleet-coordinator/src/core.rs`** — operator methods (`list_boards`,
  `who`, `logs`, `operator_power_cycle`, `grant_create`, `grant_list`,
  `grant_revoke`, `release_lease`) become `pub(crate)`; new methods for node
  list / update / delete-with-cascade and member list.
- **`crates/fleet-coordinator/src/state.rs`** — new `OrgDb` queries for the
  same: node listing / lookup by name / update / delete-with-board-cascade, and
  member listing.
- **`crates/fleet-coordinator/src/authz.rs`** — expected to need **no change**.
  If an endpoint seems to need a new rule, that is the signal to re-read §6.5,
  not to add one. The one genuinely new policy (node mutation = owner-or-admin)
  composes `node_owner` with `is_org_admin` at the call site.
- **`crates/fleet-coordinator/src/config.rs`** and **`examples/coordinator.toml`**
  — a `[github]` addition enabling the browser callback (the operator asserting
  that `<public_url>/auth/github/callback` is registered), which is what
  `GET /api/v1/auth/methods` reports.
- **`crates/fleet-coordinator/Cargo.toml`** — `include_dir`, plus whatever the
  cookie/CSRF helper needs (`hmac` is already in the lock file transitively;
  prefer reusing `sha2` over adding a cookie framework). The
  cross-compilation constraint applies to any new dependency: `ring`, no C
  toolchain, `armv7-musl` (see `docs/cross-compiling.md`).
- **`crates/fleet-coordinator/web/`** — new asset tree (D3), plus
  `src/assets.rs` to serve it and a four-line `build.rs` whose only job is
  `cargo:rerun-if-changed=web` (`include_dir!` rebuilds on a file's *contents*
  changing but not on one being added, and a contributor who hits that concludes
  the embedding is broken). The frontend's own tests live in `web-tests/`,
  **beside** `web/` and not inside it, because `include_dir!` embeds and serves
  the whole subtree.
- **`docs/ci-github-actions.md`** — deliberately **not** touched, and that is
  the answer rather than an omission: it is the consumer workload-identity
  guide, not a build-pipeline document, and this repository has no
  `.github/workflows/` at all. The one CI-relevant fact the UI introduces — the
  JavaScript tests want `node` while `cargo build` and `cargo test` never do —
  is recorded in D3 above, in `src/assets.rs` and in `tests/ui_js.rs`.
- **`docs/architecture.md`** — §3.5's route table, §6.2's carrier description,
  and §6.4's "no callback origin is involved" paragraph, plus §4.2's "approval
  is a CLI verb, not a browser form" note. Amendments the implementation must
  carry; see D1.
- **`crates/fleet-proto/src/admin.rs`** — only if a DTO needs a JSON-friendly
  view. Prefer not to touch it: a view struct belongs in the coordinator.
