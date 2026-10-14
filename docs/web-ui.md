# probefleet — coordinator web UI and browser-facing HTTP API

Status: **implemented.** This document describes the shape of the
browser surface of the coordinator: how a browser authenticates, what the
JSON API looks like, who may call each endpoint, how the assets are served, and
what the first version deliberately does not do. It is written in the register
of `docs/architecture.md` — decisions *with their costs*, accepted risks
recorded rather than fixed, and explicit "please do not 'fix' this" notes where
a future reader would otherwise undo something deliberate.

Login, signup, cookies and CSRF are
**forgs'** (`forgs-http`, merged into the coordinator's router under `/auth/*`;
see `docs/architecture.md` §6). fleet's side lives in
`crates/probefleet-coordinator/src/identity.rs` (the `AuthContext`: cookie brand
`prfs`, CSRF header `x-fleet-csrf`, cookie prefix `/api/v1/`, post-login
redirect `/`), `src/api.rs` (the `/api/v1` handlers), `src/assets.rs` (the
asset and page routes) and `web/` (the UI itself). Where this
document and the code disagree, the code is the fact and this document is the
bug.

**It reverses an earlier design choice** (no browser session on the
coordinator). See [D1](#d1-browser-identity) — the reversal is named there,
because a silent contradiction is the one outcome that would make this tree's
documentation untrustworthy.

Read `docs/architecture.md` §3.5 (routes, reverse proxy), §6.1 (identity model),
§6.2 (bearer tokens), §6.4 (bootstrapping, device flow), §6.5 (authorization)
first. This document assumes them and does not restate them.

---

## 1. The CLI surface the UI mirrors

Every management operation is available from the CLI; the UI covers the same
ground in a browser:

| what | CLI |
|---|---|
| inventory, leases, logs | `ctl list` / `ctl who` / `ctl logs` |
| board actions | `ctl lease` / `ctl release` / `ctl power-cycle` / `ctl delegate` |
| sharing | `grant <subject> …` / `grant list` / `grant revoke` |
| credentials | `auth-key create` / `auth-key list` / `auth-key revoke` |
| enrollment | `share`, `node up`, `node approve <code>` |

Besides `/ui` and `/api/v1`, the coordinator serves `GET /node/approve`
(`crates/probefleet-coordinator/src/http.rs`, `NODE_APPROVE_PAGE`): a static,
reflects-nothing page that tells you which command to run and links to
`/ui/approve` (see [§3](#3-endpoint-table)). The UI lets
users see their devices and agents, approve machines, hand out access and
manage their orgs.

---

## 2. Decisions

### D1. Browser identity

**Decided: login through forgs' browser flow with any configured provider; the
session is carried by an `HttpOnly` cookie holding the same `prfs1_` session
token the CLI uses.**

The browser surface is forgs' generic one. What the page does:

- The login page lists the configured providers from `GET /auth/providers`
  (JSON; forgs also renders an HTML list at `GET /auth/login`) and links each
  to `GET /auth/{provider}/start?return_to=<page>`, where `<page>` is the
  `/<org>/<page>` the login page was reached from (a deep link survives
  sign-in), else `/`. There is **no in-page device
  fallback**: every provider has an authorization-code flow, and the
  device flow is the CLI's.
- `GET /auth/{provider}/callback` either sets the session cookies and
  redirects to `return_to`, default `/` (a known identity) or, on **first login**, redirects to
  forgs' signup page (`/auth/signup`), where the user chooses a username. The
  ticket rides a sealed `HttpOnly` cookie; signup creates the user, the
  identity, the personal org and the admin membership in one transaction and
  then logs in. Login without a verified email is refused. fleet renders
  neither page; they are forgs' HTML, same-origin.
- The CLI's device flow (`POST /auth/device/{start,poll}`) is also forgs':
  the user confirms the code on forgs' `/auth/device` page after logging in
  in the browser with any provider.
- The session carrier is forgs' session row, delivered as
  `Set-Cookie: prfs_session=<prfs1_…>; HttpOnly; Secure; SameSite=Lax; Path=/`.
  Revocation stays "a row delete". The cookie is **a second carrier of the
  same credential, not a second credential kind**: `forgs_http::authenticate_request`
  resolves it exactly as it resolves the `Authorization` header.

**The reversal, stated loudly.** A coordinator with no web UI needs no
callback origin, and node approval could only be a CLI verb *because* "a page
served by the coordinator cannot know who is looking at it"; not bolting a
session onto the coordinator was correct then. The UI changes that. The cost
is one per-deployment setup step per provider: registering
`<public_url>/auth/<name>/callback` in its OAuth app. That step is required in
any case — CLI login also completes in the browser — and the architecture
(§6.4) says so.

**The seam this uses already exists, by design.** `http.rs::decide_pending_node`
takes an *already-resolved* subject precisely so a cookie-authenticated handler
can call the same function as the CLI route; the web approval flow
(`/<org>/approve`) does exactly that.

**`redirect_uri` is derived from `public_url`, never from the request.** Not
`Host`, not `X-Forwarded-Host`. The coordinator runs behind a reverse proxy
(§3.5) and does not see its own public name; a Host-derived callback is a
host-header-injection route to an attacker-controlled OAuth redirect. The
callback path is fixed (`/auth/{provider}/callback`) and the origin is
configuration. `return_to` is accepted only as a same-origin path.

**The signup POST is Origin-checked against `public_url`'s origin.** forgs
reduces `public_url` to bare `scheme://host[:port]` first, so a trailing slash
or a path (`https://fleet.example/sub/`) is fine. A foreign `Origin` or
`Sec-Fetch-Site: cross-site` gets 403. `Origin: null` is accepted only together
with `Sec-Fetch-Site: same-origin`. forgs ≥ 0.1.1 serves its pages with
`Referrer-Policy: same-origin`, so browsers send the real Origin. Under 0.1.0's
`no-referrer` they sent `null`, and every browser signup failed with 403
(regression test: `crates/probefleet-coordinator/tests/signup_origin.rs`).

**`Secure` is unconditional.** Browsers treat `http://localhost` and
`http://127.0.0.1` as secure contexts, so local development still works. Any
*other* plain-HTTP deployment is **unsupported for the UI** rather than
silently downgraded. Please do not make `Secure` conditional on the scheme —
that is the obvious "fix" and it would hand every session to anyone on the
path.

**Session lifetime: no silent refresh.** `session_ttl_secs` defaults to 12h.
The cookie's `Max-Age` tracks the session's `expires`, and a `401` from any
`/api/v1/*` endpoint means "log in again" — the UI bounces to its login page.
Refresh is **CLI-only**: the browser path issues no refresh token, because a
cookie-driven credential that mints is a strictly worse CSRF and XSS target
than a 12h session, and the CLI's justification (a `probe-rs` shim with no
human to re-run anything) does not apply to a tab whose user is in front of
it. `POST /api/v1/session/logout` therefore revokes just the session.

**The acting org is chosen per request.** A session is not bound to an org.
Every `/api/v1` call takes an optional `?org=<name or id>`; without it the call
acts in the user's personal org. Membership is checked there, and an org you
do not belong to answers exactly like one that does not exist (`403`). When
`GET /api/v1/session` lists more than one membership, the UI shows an **org
switcher** in the header and appends the chosen org to every call.

**Page URLs name the org: `/<org>/<page>`.** `<org>` is the acting org's path
(for a personal org, the username), e.g. `/alice/devices`, `/acme/keys`. The
UI reads it from the URL and sends it to every `/api/v1` call as
`?org=<path>`; nothing else picks the UI's acting org.

- **Landing.** `GET /` serves the shell, which resolves the session (default:
  the personal org) and `replaceState`s to `/<personal>/devices`. The
  post-login redirect is `/`.
- **Switching.** The header's org picker navigates to `/<other>/<same page>`.
  After renaming an org the UI moves to `/<new-name>/org`; after deleting one,
  to the personal org.
- **No oracle.** The page routes are static: the server serves byte-identical
  shell bytes for any syntactically valid org segment (1–64 bytes of
  `[A-Za-z0-9-]`, not a reserved name) without touching the database — it
  could not check membership anyway, because the session cookie is a
  credential only under `/api/v1/`. Membership is decided by
  `GET /api/v1/session?org=<path>`, which returns `org: null` for a
  nonexistent org and a non-member alike; the UI then renders one page, "No
  such org, or you are not a member", with a link to the personal org.
- **Reserved names.** `/{org}/<page>` would otherwise match `/api/devices`, so
  the page handler refuses every name in `state::RESERVED_NAMES` (any case) —
  the list forgs already refuses as an org or user name, which holds every
  fixed top-level prefix (`api`, `auth`, `ui`, `node`, `agent`, `client`,
  `delegate`, `healthz`, …). Static routes win in the router regardless. A new
  top-level route prefix must be added to that list; `tests/ui_assets.rs`
  checks the coordinator's prefixes against it.
- **Canonical spelling.** An id or a differently-cased path that resolves is
  rewritten (`replaceState`) to `/<name>/<page>`.
- **Legacy URLs.** `/ui` and `/ui/` redirect to `/`. `/ui/<page>?org=<id>`
  still serves the shell, and the client rewrites it to `/<name>/<page>` once
  the session API has resolved the id (no `?org=`: the personal org). This is
  client-side on purpose: a server-side id → path redirect would need either
  an unauthenticated lookup (an existence oracle) or the cookie on a non-API
  path (a carrier change). `/node/approve` still links to `/ui/approve` and
  reaches the approve page through this rewrite.
- **Renames.** Renaming an org makes links to its old path stop resolving;
  they show the uniform no-access page. That is accepted: forgs tombstones a
  released name, so nobody else can take it over, and a redirect would need an
  old-name table that does not exist.

**CSRF.** Two independent controls:

1. A **double-submit token**: `prfs_csrf` = `hex(HMAC-SHA256(k, session_token_hash))`,
   set as a non-`HttpOnly` cookie beside the session and echoed by the UI in an
   `X-Fleet-Csrf` header on every mutating call. Nothing is stored server-side.
2. The header must be **present** on every mutating call at all. A custom header
   cannot be sent cross-origin without a preflight, and the coordinator emits no
   CORS headers anywhere, so the preflight fails. The UI is same-origin by
   construction.

`k` comes from a **dedicated secret** (`csrf_secret_path`, ≥ 32 bytes, written
as `csrf.secret` by `coordinator init`), domain-separated by the app label.
It is not derived from the capability-signing seed, so rotating one secret
does not silently rotate the other. It is
**not** a per-process random: that would log every open tab out on every
restart. (A coordinator built without one — tests only — does get a random
key; `probefleet` refuses to start without the file.)

**Bearer-from-JS was rejected.** `Authorization: Bearer` from JavaScript needs
no CSRF machinery, which is its whole appeal — but a token readable by JS is a
token exfiltrable by one XSS, and this credential can power-cycle real hardware.
`HttpOnly` plus the CSRF pair is the trade this design takes. See
[§5 Threat notes](#5-threat-notes).

**Blast radius of the cookie is exactly `/api/v1/*`** (forgs'
`Carrier::ApiCookie` with fleet's `cookie_api_prefix`), plus forgs' own
explicitly marked browser pages (signup, device verification, identity
linking, `/auth/session/logout`), each of which checks CSRF itself. It is
rejected on `/agent`, `/client` and `/delegate` — a browser must never drive a
control-plane WebSocket by ambient authority, and `/delegate` mints no subject
at all — and on the JSON `/auth/*` routes (`/auth/token`, `/auth/keys`,
`/auth/logout`, `/auth/members`, `/auth/rename`), which keep requiring an
explicit bearer.

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

Response bodies are the existing `probefleet-proto::admin` DTOs — `BoardSummary`,
`LeaseHolderSummary`, `LogLine`, `GrantSummary` — serialized as JSON; they
already derive `Serialize`. One wrinkle to check at implementation time: those
types are shaped for postcard, and any that do not serialize to pleasant JSON
(newtype ids, `BoardRef`'s three parts) get a thin view struct **in the
coordinator**, never a divergent field set in `probefleet-proto`.

**The honest cost.** Today's operator methods on `Coordinator` are private, and
several verbs the UI needs **have no wire verb at all**: node tags /
adopt-policy / delete, member list (node *list* has since gained one:
`SidecarToCoord::ListNodes`, added for `ctl nodes` and sharing this document's
`list_nodes_core`). Those are
new `Coordinator` methods plus new `state.rs` / `OrgDb` queries — real
implementation work in the follow-up tasks, not plumbing. Every new query goes
through `OrgDb` so the tenancy fence holds by construction (`audit_log.ns_node_id`
is `NOT NULL REFERENCES forgs_ns_node(id)` and the table is reachable only through
`OrgDb`; that combination is what makes "no code path can forget the org check"
true).

### D3. Frontend stack and asset serving

**Decided: hand-written HTML plus plain ES modules using `fetch`, embedded in
the binary. No npm, no bundler, no TypeScript compile, no build step at all.**

- Source lives in `crates/probefleet-coordinator/web/` — not a `web/` at the repo
  root, not a `fleet-web` crate. The assets are part of the binary that serves
  them.
- Embedded with `include_dir!`; assets are served under `GET /ui/a/*`, pages
  at `/<org>/<page>`. The coordinator stays
  a single cross-compilable binary behind a reverse proxy (§3.5).
- **A `cargo build` with no node/npm installed keeps working — structurally, not
  as a fallback.** There is no build script, no generated artifact, nothing to
  keep in sync, so there is no state in which the check could fail. That is the
  reason this stack was chosen over a nicer one.
- Strict CSP on every UI response:
  `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. No
  inline script, no CDN.

**Four implementation decisions** (`crates/probefleet-coordinator/src/assets.rs`
carries the same notes at the call site):

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
2. **No global `Router::fallback`, anywhere.** The asset catch-all is scoped
   under `/ui/`, and the client-side routes are listed explicitly — one
   `/{org}/<page>` pair per page, refusing reserved org segments. That is what makes
   "the shell cannot swallow `/api/*`, `/agent`, `/client`, `/delegate`,
   `/healthz` or `/node/approve`" a property of the router's *shape* rather than
   of a test that samples it, and it is why an unknown top-level path is an
   empty 404. The instinct when a new client-side route 404s is to add
   `.fallback(shell)`; the answer is to add the page to `PAGES` in
   `src/assets.rs`, from which the router derives both the bare `/<org>/<page>` and
   the trailing-slash `/<org>/<page>/` spelling (plus the legacy `/ui/<page>`
   pair). Both are registered because the
   client router strips a trailing slash, so serving only the bare form made a
   *cold* load of `/alice/devices/` a 404 that navigation within the shell never
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

**CI.** `.github/workflows/ci.yml` builds the workspace and runs the
coordinator and CLI test suites; with a zero-build frontend there is no
frontend build step to add. If D3 is ever revisited, the revisit has to bring
a pipeline with it: a bundled frontend means a build step whose output must be
in the binary, which means either a checked-in artifact (drifts) or a `cargo
build` that needs node (breaks the cross-compilation story in
`docs/cross-compiling.md`). (`docs/ci-github-actions.md` is the *consumer*
workload-identity guide, not a build-pipeline document.)

The frontend's unit tests
(`crates/probefleet-coordinator/web-tests/*.test.mjs`, node's built-in runner, zero
npm dependencies) want `node` on `PATH`. `tests/ui_js.rs` runs them when it is
there and prints a loud skip when it is not, so neither `cargo build` nor `cargo
test` requires a JavaScript toolchain — at the honest cost that on a machine
without node that coverage silently disappears. The hosted runner `ci.yml`
uses ships node, so CI runs them. Note also that
`include_dir!` embeds the *whole* subtree, which is why those tests live in
`web-tests/` beside `web/` rather than inside it — anything under `web/` ships in
the binary and is publicly served.

### D4. v1 scope fence

**In:** read-only inventory (boards, leases, nodes, grants, auth keys, audit
log), plus the management verbs — power-cycle, release someone else's lease as
admin, node tags / adopt-policy / delete (**not** rename; see §3), pending-node
approval, grant
create / list / revoke, auth-key mint / list / revoke, team-org creation and
member management (add, change role, remove).

**Out**, each with its reason:

- **No lease acquisition from the browser.** Worth arguing rather than
  asserting: a lease taken in a browser has no sidecar to use it. The lease is
  only useful to a machine running `probe-rs`, so a browser button would be
  "reserve this board for me", which is a real feature — and it immediately wants
  a holding/extending/expiring UI (heartbeats come from the sidecar; a browser
  tab that closes leaves a board held until TTL), a way to hand the lease to a
  sidecar, and a story for what a queued request looks like in a page that is
  not polling. Deliberately unscheduled, not
  refused forever.
- **No data-plane or board console.** Nothing relays probe-rs traffic to a
  browser. That would mean a second relay ingress with a browser-shaped
  credential.
- **No `delegate`.** It hands out a capability token; see the threat notes.
- **No invites/join requests.** An
  admin adds an *existing* user by username (one who has logged in at least
  once); there is no email or link invite and no way to ask to join. Orgs can
  be created (any logged-in user, gated by `allow_org_creation` /
  `max_orgs_per_user`), and renamed or deleted by their admins.
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
`Authorization: Bearer <session>` header, is authenticated by
`forgs_http::authenticate_request` (the one place a credential becomes a
subject), acts in the org named by `?org=` (default: the personal org;
membership checked), and returns `application/json`. Mutating calls
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
  node by its node-local `name`, which is `UNIQUE (ns_node_id, name)`, resolved
  within the acting org.

### Session

Login itself is forgs' (D1); these are the routes the UI touches.

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /auth/providers` | — | the configured provider names (JSON) | forgs | anyone (reveals only which logins this deployment offers) |
| `GET /auth/{provider}/start?return_to=/<org>/<page>` | — | `302` to the provider; `state` (+ PKCE verifier) in a sealed `HttpOnly` flow cookie | forgs | anyone |
| `GET /auth/{provider}/callback?code&state` | — | known identity: `302` to `return_to` (default `/`), `Set-Cookie: prfs_session`, `Set-Cookie: prfs_csrf`; first login: `302 /auth/signup` with a sealed ticket cookie | forgs | anyone with a valid `state` |
| `GET`/`POST /auth/signup` | username | forgs' HTML form; on success the cookies above | forgs | holder of a signup ticket |
| `GET /api/v1/session[?org=]` | — | `{"user_id","username","memberships":[{"id","name","role"}],"org":{"id","name","role"}\|null,"expires","can_create_orgs"}` | forgs store | any session |
| `POST /api/v1/session/logout` | `{}` | `204`, cookies cleared | `forgs_http::session::logout` | any session |

`memberships` drives the org switcher; `org` is the org this request acted in
(`?org=`, default the personal org), `null` if the user does not belong to the
requested one. `can_create_orgs` is `true` when the deployment allows
self-service org creation and the user is under `max_orgs_per_user`; the UI
shows the create form only then. `expires` lets the UI bounce to login *before* the next call
`401`s. The page never sees a token: no route on this surface returns one in a
body (the old `/api/v1/session/device/*` and `/api/v1/auth/methods` routes are
gone with the device fallback).

### Orgs and membership

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/org[?org=]` | — | `{"id","name","role","personal"}` | forgs store | member |
| `GET /api/v1/org/members[?org=]` | — | `[{"user_id","username","role"}]` | `NsScope::list_members` | member |
| `POST /api/v1/orgs` | `{"name"}` | `201 {"id","name","role":"admin"}` | namespace creation + admin membership for the caller; audited `org.create` in the new org | any session, if `allow_org_creation` and under `max_orgs_per_user` |
| `POST /api/v1/org/members[?org=]` | `{"username","role":"member"\|"admin"}` | `204` (adds the user, or changes an existing member's role) | `forgs_http::members::set`; audited `member.set` | **admin** |
| `DELETE /api/v1/org/members/{username}[?org=]` | — | `204` | `forgs_http::members::remove`; audited `member.remove` | **admin** |
| `POST /api/v1/org/rename[?org=]` | `{"name"}` | `200 {"id","name","role":"admin","personal":false}` | `forgs_http::members::rename_namespace`; audited `org.rename` (detail `from <old>`) | **admin**, team orgs only |
| `DELETE /api/v1/org[?org=]` (alias `POST /api/v1/org/delete`) | — | `204` | fleet emptiness check + history purge, then `forgs_http::members::delete_namespace`; audited `org.delete` | **admin**, team orgs only, empty orgs only |

**Creating an org.** Any logged-in user can create a team org and becomes its
admin; the UI's "Org" page has a create form and switches into the new org on
success. `POST /api/v1/orgs` ignores `?org=` — the new org has no parent to act
in. The name must be a single path segment of lowercase letters, digits and
`-` (no leading, trailing or doubled `-`), not a reserved name, and the
display name must equal its canonical form. Refusals: `400 invalid_name`
(bad name), `409 name_taken` (collides with an existing org, a username, or a
tombstoned name), `403 org_creation_disabled` (`allow_org_creation = false`),
`403 org_limit_reached` (the user already created `max_orgs_per_user` team
orgs; `0` means unlimited). The cap counts team orgs the user created and is a
hard cap: forgs' `create_namespace` creates the node, the admin membership and
checks the cap in one transaction, so concurrent creates cannot overshoot it.
The host-shell `coordinator org create <name> --admin <username>`
remains the escape hatch and ignores both keys.

**Renaming and deleting an org.** An admin of a *team* org can rename it
(`POST /api/v1/org/rename`, same name rules and refusals as create:
`400 invalid_name`, `409 name_taken`) or delete it (`DELETE /api/v1/org`).
The old name is tombstoned either way — nobody can take it again. A user's
personal org follows their username and is refused with `409 personal_org`;
a member gets `403 forbidden`. Delete is refused with `409 org_not_empty`
while nodes, boards, open leases or unexpired grants reference the org:
remove the nodes, release the leases and revoke the grants first. The
trade-off of an accepted delete: the org's fleet *history* — closed leases and
the fleet audit log (node and board events) — is purged with it, because those
rows reference the namespace `ON DELETE RESTRICT`; forgs' identity audit
(including `org.delete` itself) is kept. Memberships and any API keys scoped
to the org (auth keys) go with the namespace (forgs cascades them). The
purge and the namespace delete are two transactions; a node enrolled in
between fails the delete (`org_not_empty`) and loses only history. The Org
page shows rename and delete controls to admins of a team org
(`SessionView` and `GET /api/v1/org` carry `personal`); the CLI has
`probefleet org rename <new>` and `org delete [--yes]`.

**Managing members.** Admins get an editable members panel — add by existing
username with a role dropdown, change a role, remove; non-admins see the same
list read-only. The mutating routes call `forgs_http::members::{set,remove}`
directly, the same functions behind forgs' `/auth/members`, so the browser and
the CLI (`probefleet org members …`, which uses `/auth/members` with the
fleet file's session) share one implementation; CSRF is the existing
double-submit. Errors: `403 forbidden` (not an admin of the acting org),
`404 not_found` (no such user — they must have logged in once — or no such
member), `409 last_admin` (removing or demoting the last admin, which would
leave the org unmanageable), `400 invalid_request` (malformed body or role).

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

There is deliberately **no** `GET /api/v1/nodes/pending`, for the reason §4
records:
a pending row's namespace is `NULL` until an approval binds it, so there is no
attribution to filter a listing on, and a member-visible list of live codes
would be exactly the cross-tenant index §4 forbids. Approval stays code-driven.
Attributing pending rows to an org is a separate design question, not
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
`probefleet_proto::lease::parse_constraint` — where a bare word is always a tag —
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

### Auth keys (forgs API keys)

All three take `?org=` like every other call; the key belongs to the acting org.

| Method + path | Request | Response | Calls | Who |
|---|---|---|---|---|
| `GET /api/v1/auth-keys` | — | `ApiKeyList` (hashes only) | `forgs_http::keys::list` | member |
| `POST /api/v1/auth-keys` | `{"tags":[…],"ttl_secs":N,"multi_use":false,"purpose":"node"\|"ci","ops":[…],"subject_name":"builder"\|null}` | `ApiKeyCreated` — **the only time the secret (`prfk1_…`) exists** | `forgs_http::keys::create` (tags/ops become the key's payload) | member |
| `DELETE /api/v1/auth-keys/{hash_prefix}` | — | `ApiKeyRevoked` | `forgs_http::keys::revoke` | key creator, or admin |

`ttl_secs = 0` is a `400` and the TTL is capped at 30 days
(`Ttls::api_key_max`), exactly as on `/auth/keys` — the same
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
  echoed `ApiKeyCreated.subject_name` may differ from what was sent — display
  the echo, not the input;
- `"purpose":"agent"`. That spelling is **CLI-only sugar** for `ci` and is not a
  wire value; the allowlist here is still exactly `node` / `ci`.

`ApiKeyCreated` and each `ApiKeyInfo` echo `subject_name`, so a listing can
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
| `GET /` | the shell (the landing page; the client moves to `/<personal>/devices`), `Cache-Control: no-cache` |
| `GET /<org>/<page>`, with or without a trailing slash (`/alice/devices`, `/alice/devices/`, … for `devices`, `agents`, `approve`, `access`, `keys`, `org`, `audit`) | the shell, byte-identical for every org segment; `404` if the segment is not 1–64 bytes of `[A-Za-z0-9-]` or is a reserved name |
| `GET /ui`, `GET /ui/` | `302` → `/` |
| `GET /ui/<page>[/]` (legacy, `?org=<id>`) | the shell, which rewrites the URL to `/<org>/<page>` client-side |
| `GET /ui/a/{tree-hash}/{path}` | one embedded asset, `public, max-age=31536000, immutable` |
| `GET /node/approve` | unchanged URL, unchanged reflection-free page, plus one static link to `/ui/approve` (legacy; rewritten client-side) |

All of them carry the CSP and hardening headers above, authenticate nothing and
set no cookies — the shell has to load before a session exists, because login is
a page inside it. A page path that is not a known page (e.g. `/alice/app.mjs`, `/ui/nope.mjs`)
is a `404`
rather than the shell, which is what makes a typo'd `import` surface as a broken
import instead of as HTML parsed as JavaScript.

`/node/approve` keeps its path because deployed agents print it. The page's
"reflects nothing" property holds: it has a static paragraph
linking to `/ui/approve`, where the same JSON endpoint is driven from a real
form, and it reads no query parameter and renders byte-identically
whatever the query string. The form itself is deliberately not there — that would put
attacker-supplied text on an unauthenticated page.

---

## 4. Authorization on the new surface

**Deny by default.** Every endpoint resolves to a `Subject` and is checked
against the *target object's* org through the existing evaluator —
`authz::require_role`, `authz::board_access`, `authz::require_lease_control`,
`probefleet_core::access::Access`. Nothing on this surface evaluates access itself.

| Endpoint group | Rule | Where it already lives |
|---|---|---|
| boards list, leases list | non-empty `Access` (own-org membership, or a live grant) | `authz::board_access` |
| power-cycle | `Access` + `AllowedOp::PowerCycle` for a grantee | `Coordinator::operator_power_cycle_core` |
| lease release | **holder, or the board org's admin** | `authz::require_lease_control` |
| grant create | **admin** | `require_role(Admin)` |
| grant list | membership | `require_role(Member)` |
| grant revoke | **creator, or admin** | `Coordinator::grant_revoke_core` |
| auth-key mint / list | membership | `forgs_http::keys` (membership of the target org) |
| auth-key revoke | **creator, or admin** | `forgs_http::keys::revoke` |
| audit log | **admin** | `Coordinator::logs_core` (+ `OrgDb` scoping, a second independent fence; forgs' identity audit rows are merged in, unfiltered view only) |
| org / member list | membership | `require_role(Member)` in the acting org |
| member add / set-role / remove | **admin** (+ last-admin guard) | `forgs_http::members::{set,remove}` |
| org create | any session, gated by `allow_org_creation` / `max_orgs_per_user` | new; not scoped to an acting org |
| org rename / delete | **admin**, team orgs only (`409 personal_org`); delete only when empty (`409 org_not_empty`) | `Coordinator::{rename,delete}_org_core` → `forgs_http::members::{rename,delete}_namespace` |
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
**there is no pending-registration listing**. A pending row's namespace
(`forgs_pending_device.ns_node_id`) is `NULL` until an approval binds it, so a
listing has no attribution to filter
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
`POST /api/v1/auth-keys`'s `ApiKeyCreated.key` — is not one of these, and the
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

- **No rate limiting anywhere in the coordinator.** `/auth/{provider}/start` is
  as unauthenticated as `/auth/device/start`, with no credential exposure.
- **Device-flow remote phishing** (RFC 8628 §5.4), for CLI login and,
  sharpened, for node approval (§6.4).
- **Unauthenticated pending-row growth** (CLI logins and node registrations
  share forgs' pending table), capped by `max_pending_nodes`
  (default 256) and reclaimed by the TTL sweep.

Adding rate limiting is a coordinator-wide change and belongs in its own task,
not smuggled in with a UI.

---

## 6. Where it lives

- **`crates/probefleet-coordinator/src/api.rs`** — the `/api/v1/*` handlers. They
  authenticate through forgs' `authenticate_request` with the cookie carrier
  allowlisted for this prefix only, and call the same coordinator methods the
  CLI's routes do.
- **`crates/probefleet-coordinator/src/identity.rs`** — the forgs `AuthContext`
  (cookie brand, CSRF header, cookie prefix, post-login redirect) and fleet's
  hooks.
- **`crates/probefleet-coordinator/src/http.rs`** — `/node/*`, including the
  informational `GET /node/approve`; the browser approves through
  `POST /api/v1/nodes/pending/{code}`, which calls the same
  `decide_pending_node` and shares its membership check.
- **`crates/probefleet-coordinator/src/authz.rs`** — the authorization rules. If an
  endpoint seems to need a new rule, that is the signal to re-read §6.5 of the
  architecture, not to add one; node mutation (owner-or-admin) composes
  `node_owner` with `is_org_admin` at the call site.
- **`crates/probefleet-coordinator/web/`** — the asset tree (D3), served by
  `src/assets.rs`. A four-line `build.rs` emits `cargo:rerun-if-changed=web`
  (`include_dir!` rebuilds on a file's *contents* changing but not on one being
  added). The frontend's own tests live in `web-tests/`, **beside** `web/` and
  not inside it, because `include_dir!` embeds and serves the whole subtree.
- Any new dependency is bound by the cross-compilation constraint: `ring`, no C
  toolchain, `armv7-musl` (see `docs/cross-compiling.md`).

**Deliberately unscheduled:** lease acquisition, delegation, board console,
and invites / join requests.
