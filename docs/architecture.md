# probefleet — Architecture

Status: **accepted; scaffolding**. The system is single-stack postcard-rpc for
both data and control planes (§3), carried over WebSocket behind an HTTPS
reverse proxy (§3.5). Callers authenticate with bearer tokens; identity, login,
sessions, orgs and API keys live in [forgs](https://github.com/kaspar030/forgs)
(§6). The fleet is multi-tenant, with orgs, users and nodes as first-class
subjects (§6.1), and enrollment is rooted on the user rather than the
coordinator operator (§6.4). This document records the agreed shape of the
system and the decisions still open. It is deliberately concrete about how the
pieces map onto the real `probe-rs` CLI surface that
[ariel-os / laze](../../ariel-os/laze-project.yml) emits.

There is no private CA and no mTLS: client certificates, CSR issuance and
cert-fingerprint pinning of clients were withdrawn in favour of bearer tokens
(§6.2). Capability tokens (§6.3) are orthogonal to connection auth.


## 1. Problem

Many developers and CI jobs want to use embedded dev boards that are physically
connected to a number of Raspberry Pis. We want **remote board use to feel
almost identical to local board use**: an ariel-os developer runs
`laze … run` and it Just Works against a board in the lab, with no edits to the
ariel-os/laze recipes.

probe-rs already ships a client/server split, but it has no concept of a
*board*, and nothing for concurrent-use scheduling, time-based scaling, USB
power handling, or multi-user auth. We build those around probe-rs rather than
inside it.

## 2. Topology (decided)

```
   dev workstation / CI                coordinator (hosted)             Raspberry Pi / laptop "node"
 ┌───────────────────────┐           ┌──────────────────────┐         ┌──────────────────────────┐
 │  laze … run           │           │  sqlite state        │         │  probe discovery         │
 │    │                  │           │  orgs/users/grants   │         │  USB power (uhubctl/gpio)│
 │    ▼ (real probe-rs   │  WSS +    │  scheduler / leases  │  WSS +  │  probe-rs (child `serve` │
 │     CLI args)         │  bearer   │  auth / quotas       │  bearer │   process per board)     │
 │  fleet sidecar  ──────┼──────────▶│  RELAY (data plane)  │◀────────┼──  fleet agent           │
 │  (probe-rs shim)      │  (dials   │  /auth/* (device flow│ (node   │                          │
 └───────────────────────┘   in)     └──────────────────────┘  dials  └──────────────────────────┘
                                      behind an HTTPS proxy    OUT)
```

Key constraints that drove this shape:

- **No direct workstation→node connection.** All traffic relays through the
  coordinator. Nodes live behind NAT on lab networks; the coordinator is the
  only publicly reachable component.
- **Nodes dial out.** The node opens a persistent WSS connection *to* the
  coordinator. Over that one connection the coordinator can also call *into*
  the node (see §5). No inbound ports on the Pis.
- **The coordinator sits behind an HTTPS reverse proxy** and speaks WebSocket
  over it (§3.5). It terminates no TLS of its own in the hosted deployment.
- **One host may hold several roles at once.** A laptop is routinely both a
  *user* (leasing fleet boards) and a *node* (offering its own probes). The
  credential model must express that without two disjoint enrollments (§6.4).
- **Single multi-role binary** (`probefleet`), role chosen by subcommand:
  `node`, `coordinator`, `sidecar`, `ctl`, plus the user verbs `login`,
  `share`, `grant`.

## 3. Transport: postcard data plane, typed control plane, over WSS (decided)

Key fact (confirmed by reading the source): **probe-rs's client/server mode is
[`postcard-rpc`](https://docs.rs/postcard-rpc) 0.12.** That crate abstracts its
wire behind `WireTx` / `WireRx` / `WireSpawn` traits — its stock host transports
are all point-to-point (`raw_nusb`, `serial`, `webusb`), but
`HostClient::new_with_wire(tx, rx, spawn)` accepts *any* wire impl. This is the
seam we build on. It splits the problem cleanly into two planes:

### Data plane — opaque WebSocket-over-TCP tunnel

The sidecar speaks **vanilla probe-rs**. In probe-rs 0.31/0.32 the client/server
link is a **WebSocket** (route `/worker`) over TCP (see §4.2; verified against
the probe-rs sources, upstream analysis in #1965 / #3322). We do **not** parse or re-implement
it — we tunnel the raw bytes of that
connection:

```
  sidecar's probe-rs client  ──WebSocket/TCP bytes──▶  [ WSS to coordinator ]
      ──relay──▶  [ WSS to node ]  ──▶  node's `probe-rs serve`
```

The coordinator forwards opaque bytes on a leased channel; it never decodes
probe-rs traffic. The same relay carries two more channel kinds: a gdb tunnel
(`ChannelKind::Gdb`) and a board's USB serial port (`ChannelKind::Serial`,
§4.2 "Serial passthrough"). The sidecar exposes a local TCP endpoint (advertised to the
genuine client as `PROBE_RS_REMOTE_HOST=ws://127.0.0.1:<port>`) and byte-splices
its accepted connection onto the relay — the same bytes flow through verbatim.

### Control plane — leases, inventory, auth, power, heartbeats

Small typed request/response + a few server→client pushes.

> **DECISION (accepted):** myelin is dropped. We use **postcard for both
> planes**. Coordinator→node commands ride the node's single dial-out
> connection; the opaque data channel is multiplexed over the same pipe.
> Revisit only if control ergonomics force it.

### 3.5 WebSocket over HTTPS (decided)

The postcard frames (`probefleet-wire`) are carried as **WebSocket binary messages
over HTTPS**, not over a bespoke length-prefixed TCP protocol. Drivers, in
order of force:

1. **Deployment behind an HTTPS reverse proxy is a requirement.** A proxy cannot
   route a bespoke TCP protocol; it would need `stream`-mode passthrough on a
   second port, forfeiting HTTP routing and splitting the listener story.
2. **Bearer auth gets a natural carrier** — `Authorization: Bearer …` on the
   WebSocket upgrade request, rather than an auth frame hand-rolled into the
   `Hello` handshake.
3. **Browser and device login need HTTP endpoints anyway** (§6.4); they share the port
   and the proxy.
4. **Port 443 traverses corporate firewalls and lab NAT**, which a custom port
   does not.
5. **probe-rs already speaks WebSocket** (`/worker`), so the whole stack becomes
   one protocol family.

WebSocket delimits messages, so there is no length prefix: `probefleet-wire`'s codec
is a thin adapter over WS binary payloads carrying the `probefleet-wire` envelopes,
the relay's byte-opaque splice, and every `probefleet-proto` payload type.

Routes:

| Route | Who | Purpose |
|---|---|---|
| `GET /agent` (WS upgrade) | nodes | persistent dial-out control + data |
| `GET /client` (WS upgrade) | ctl + sidecar | leases, relay channels, admin surface |
| `GET /delegate` (WS upgrade) | a sandboxed agent | **relay only**, authorised by a capability token; no principal (§6.5) |
| `/auth/*` | — | **forgs' router**, merged in: `/auth/providers`, `/auth/login`, `/auth/{p}/start` + `/callback`, `/auth/signup`, `/auth/device/*` (CLI login), `/auth/token` (refresh, refresh-token, workload OIDC and `ci` API-key exchange), `/auth/logout`, `/auth/session`, `/auth/keys`, `/auth/members`, `/auth/rename` (§6.4) |
| `POST /node/register/start` | headless nodes | begin an approval-pending registration (§4.2 rung 3) |
| `POST /node/register/poll` | headless nodes | redeem an approved registration for a node token |
| `POST /node/register/approve` | org members | inspect / approve / deny a pending registration |
| `POST /node/enroll` | holder of a `node` API key | redeem it for a node token (§6.4) |
| `POST /node/self-register` | org members (session) | register the calling machine (`share`) |
| `GET /node/approve` | anyone | static page: what to run to approve one (and a link to `/ui/approve`) |
| `GET /api/v1/*` | a browser session, or a bearer | the browser-facing JSON API (`docs/web-ui.md` §3) |
| `GET /` | a browser | the web UI's shell (landing; moves to `/<personal>/devices`) |
| `GET /<org>/<page>`, with or without a trailing slash | a browser | the web UI's shell, embedded in the binary (`docs/web-ui.md` D3); reserved names as `<org>` are a 404 |
| `GET /ui`, `GET /ui/` | a browser | 302 to `/` |
| `GET /ui/<page>[/]` | a browser | legacy: the shell, rewriting `?org=<id>` to `/<org>/<page>` client-side |
| `GET /ui/a/{hash}/*` | a browser | one embedded asset, immutably cacheable |
| `GET /healthz` | proxy | liveness |

The browser pages under `/auth/*` (login, callback, signup, device
verification), `/api/v1/*`, `/`, `/<org>/<page>` and `/ui*` are the **browser surface**, added by
`docs/web-ui.md` and designed there rather than here — named by prefix rather
than by position, so the next row anyone adds to this table does not silently
leave this sentence pointing at the wrong rows. Three properties of it belong
here rather than only in that document:

* `/api/v1/*` is the **only** prefix on which a session cookie is an accepted
  credential. Every other route in this table requires an explicit
  `Authorization: Bearer`, including `/agent`, `/client` and `/delegate` (a
  browser must never drive a control-plane WebSocket by ambient authority) and
  the JSON `/auth/*` routes (`/auth/token`, `/auth/keys`, `/auth/logout`, …);
  forgs' own browser pages under `/auth/*` are the explicitly marked exception.
* Mutating `/api/v1` calls whose credential arrived in a cookie must also carry
  an `X-Fleet-Csrf` header, and the coordinator emits **no CORS headers
  anywhere**, which is what makes that header a second independent control.
  Every mutating `/api/v1` route (logout, the node verbs, grants, auth keys,
  orgs and members, power-cycle, lease release) sits behind that same single
  check.
* **The page and `/ui*` routes authenticate nothing and there is no global
  router fallback.** The shell has to load before a session exists, since login is a
  page inside it, so the asset routes are unauthenticated and set no cookies;
  they serve only bytes compiled into the binary — the same shell for every
  `/<org>/<page>`, so a page URL is no org-existence oracle. The asset
  catch-all is scoped under `/ui/`, each page is an explicit `/{org}/<page>`
  route, and that handler refuses every `RESERVED_NAMES` entry (which holds
  every fixed top-level prefix; a new prefix must be added there), which is what makes "the UI cannot swallow another prefix" a
  property of the router's shape rather than of a test — an unknown top-level
  path is an empty 404. Please do not add `.fallback(...)` to fix a
  client-side route that 404s; add the page to `PAGES` in
  `crates/probefleet-coordinator/src/assets.rs`, which registers both its bare and
  its trailing-slash spelling.

**Keepalive is now load-bearing.** A proxy in front means idle WebSockets are
reaped on a timeout we do not control, so the node connection must run
ping/pong keepalive, and the existing reconnect backoff stops being a nicety.
Both sidecar-direction routes share one handshake + keepalive implementation
(`server::sidecar_pump`); `/delegate` differs only in its per-message handler,
so it cannot forget to ping.

`GET /delegate` is the one authenticated route that constructs **no**
`Subject`. It hex-decodes the bearer as a signed capability token, verifies the
signature with the coordinator's own key, checks expiry, and checks the lease
is still live — which is what makes "revoke by releasing the lease" immediate
rather than "once the token expires". After the upgrade a flat message
allowlist applies: `OpenChannel` (only for the token's own lease), `Data` and
`CloseChannel`, and nothing else. Every rejection is the same `401`. See §6.5.

**Cross-compilation constraint:** the WS implementation must build for
`armv7-musl` / `aarch64` (Raspberry Pi nodes). `tokio-tungstenite` on rustls
with the `ring` provider is the intended choice; verify early, as this is the
same constraint that forced `ring` over `aws-lc-rs`.

### TLS is an I/O-layer concern

In the hosted deployment the reverse proxy terminates TLS and the coordinator
speaks plain HTTP on loopback; in a self-hosted deployment the coordinator may
terminate TLS itself. Either way the framing above is unchanged. `probefleet-tls`
is only client-side trust configuration: normal WebPKI roots by default,
plus an optional pinned server-cert fingerprint for local/self-hosted
deployments with no public DNS (§10). There are no **client** certificates
anywhere in the system.

## 4. Roles

### 4.1 `coordinator`
Central daemon, single node, sqlite (via `sqlx`) for state. Responsibilities:

- **Inventory:** reconcile board reports from all agents into one fleet view.
- **Scheduling & leases:** match constraint requests to idle boards; queue when
  none free; lease TTL + heartbeat renewal; fairness/quotas.
- **Auth:** authenticate bearer tokens → a [`Subject`](#61-identity-model);
  evaluate grants; issue per-lease capability tokens.
- **Relay (data plane):** splice a sidecar's probe-rs session to the owning
  agent. The coordinator does **not** parse probe-rs traffic; it forwards
  opaque framed payloads on a leased channel. Restartable without dropping
  active TLS sessions within lease TTL is a goal, not a v1 guarantee.
- **Audit log:** who leased what, when, power events, faults.

Does **not** touch USB.

#### Config & scaffolding (`coordinator init`)

The coordinator reads a TOML config, discovered at the XDG path
`~/.config/probefleet/coordinator/coordinator.toml`; `--config` /
`PROBEFLEET_CONFIG` override it. Generated key material and the SQLite
database default to `~/.local/share/probefleet/coordinator/`.

`probefleet coordinator init` scaffolds a ready-to-run coordinator:

- generates a fresh ed25519 capability-token signing seed
  (`signing.seed`, 64 hex chars, `0600`);
- generates a fresh cookie/CSRF secret (`csrf.secret`, `0600`, ≥ 32 bytes),
  referenced by `csrf_secret_path` — dedicated, **not** derived from the
  signing seed (§6.2);
- writes a populated `coordinator.toml`: `listen_addr` (loopback by default,
  since an HTTPS reverse proxy fronts it), `public_url` (the externally
  reachable origin handed to clients and nodes, and the only source of OAuth
  `redirect_uri`s), a commented `[[auth.providers]]` example (§6.4), and the
  lease policy. An empty provider list is a supported deployment (air-gapped,
  or development): nobody can log in through a browser or `login`, and
  `coordinator user-token --username X` remains the bootstrap path.

It generates no CA, server cert or server key: TLS is the reverse proxy's job
(§3.5). `init` refuses to overwrite existing files unless `--force` is passed.

Minting an API key **does not require a shell on the coordinator host**: any
org member mints one with
`probefleet auth-key create [--org O]`, authenticated by their `[user]` session. The
`coordinator auth-key` / `auth-keys` / `auth-key-revoke` verbs remain for the
self-hosted operator, for the air-gapped case, and for the one thing the API
refuses — a key that never expires. `coordinator auth-key` takes the same
`--purpose` / `--ops` as the API path, so a never-expiring **CI** key
(`--purpose ci --ttl 0`) is mintable here and only here; the grant its
redemption synthesises is still capped at 30 days and renewed on each
redemption, so a perpetual key is a rolling share, not a perpetual one.

#### Per-fleet config layout

**Config is per *fleet*, not per role.** A machine that is both a user and a
node (the laptop dual-role case, §6.4) holds both credentials in one file,
told the coordinator address and trust material once:

```
~/.config/probefleet/fleets/<name>.toml
```

```toml
# The fleet's coordinator.
url = "https://fleet.example.com"
# Optional: pinned server-cert SHA-256, for self-hosted deployments
# without a publicly trusted certificate.
# server_cert_sha256 = "…"

[user]                 # present once `login` has run
session_token = "…"    # prfs1_…, short-TTL bearer, refreshable
username = "kaspar"    # display only; identity is the immutable user id
expires = 1788600000
refresh_token = "…"    # prfr1_…: the DURABLE credential that renews the
                       # session above without a browser (§6.4)

[node]                 # present once `share` / `node up` has run
node_token = "…"       # prfn1_…, long-lived machine bearer, auto-rotating
node_id = "01J9Z…/kaspar-laptop"   # "<org id (ULID)>/<name>"
coordinator_token_pubkey = "…"   # verifies per-lease capability tokens

[agent]                # present once `agent login` has run (§6.7)
auth_key = "…"         # prfk1_…, the DURABLE credential, re-redeemed on demand
name = "desk-bot"      # the `--name` identity; display only, not verified
workload_token = "…"   # the current short-lived session
expires = 1788999999   # required here, so staleness is knowable offline
```

**`[user]` names no org.** A session is not bound to one: each command acts in
the org named by `--org` (a name or id), defaulting to the user's personal org
(§6.1). Ids are immutable ULIDs and names are handles, so nothing stored here
goes stale when a user or org is renamed, and nothing is keyed on a provider
login.

A laptop that both consumes and provides simply has **both tables**. A headless
Pi has only `[node]`. A CI runner has neither (it exchanges a workload token per
job). A persistent sandbox has `[agent]` (§6.7). `--fleet <name>` /
`PROBEFLEET` select among several fleets; `default`
is used otherwise. Credentials are stored `0600`; the two tokens stay **distinct**
by design (§6.4).

There is no separate `agent.toml` / `client.toml`: `AgentConfig` is not a file
format at all; the `node run` role assembles it from the fleet file's `[node]`
table plus node-local settings.

Node-local, non-credential settings live in `~/.config/probefleet/node/`
(`node.toml` for boards path / heartbeat / erase-on-release, `boards.toml` for
the inventory). They describe the *machine*, not the fleet, so they are not
per-fleet and are not duplicated when a machine joins a second one.

The credential env var is a single `PROBEFLEET_TOKEN`; the selector
vars are `PROBEFLEET_BOARD` (a board **model**), `PROBEFLEET_ID` and
`PROBEFLEET_SELECT` (`sidecar --board` / `--id` / `--select` override
them, §7). `PROBEFLEET` selects a fleet by name.

**Writers are read-modify-write plus atomic rename.** A laptop has two
independent writers — `login` refreshing `[user]`, a running agent persisting a
rotated `[node]` token — so each patches only its own table. The residual race
is a lost update, recoverable by re-running the command; there is no file
locking in v1. The asymmetry justifies the cost: re-running `login` is a browser
tab, whereas clobbering a node credential is a physical visit to the Pi.

`[agent]` adds a **third writer, and the high-frequency one**: every `ctl`
invocation and every `probe-rs` shim invocation on a sandbox re-redeems the
stored auth key once the workload token is within `REFRESH_SKEW_SECS` (60s) of
expiry. It needs no locking, for a reason specific to it: re-redeeming a
**multi-use** API key is not a rotation. forgs' `consume_api_key` stamps
`consumed_at` only when `single_use != 0`, so each redemption mints an
independent workload token and upserts the *same* grant row — nothing is
invalidated, N concurrent redemptions all succeed, and every resulting token
stays valid. There is no correctness race to lose, only churn.

The churn is damped by **re-reading the file immediately before redeeming**, not
only on failure: a process that finds a peer's fresher token on disk uses it and
redeems nothing. Jitter and lock files are deliberately not added — they would
buy correctness that is not at stake. Correspondingly there is no
`previous_workload_token` mirroring `[node]`'s: that field exists because
rotation can lose an ack, and nothing here is ever invalidated.

Config and database formats carry no migration path from earlier layouts: an
upgrade across an identity-model change means re-`login` and re-enrolling
every node.

#### End-to-end deployment flow

```sh
# 1. On the coordinator host: scaffold signing key, CSRF secret + config.
probefleet coordinator init --public-url https://fleet.example.com
#    Register an OAuth app with any provider (GitHub, Codeberg, GitLab, OIDC)
#    whose callback is <public_url>/auth/<name>/callback, add it as an
#    [[auth.providers]] entry in coordinator.toml, then start the
#    coordinator behind your HTTPS reverse proxy.
probefleet coordinator

# 2. On your laptop: log in. Opens a browser (or prints a URL + code when
#    headless); log in with any provider, choose a username the first time.
probefleet login --fleet-url https://fleet.example.com
#    → personal org created at signup; session cached in fleets/default.toml

# 2b. Optional: a team org. Any logged-in user can create one and becomes its
#     admin (gated by allow_org_creation / max_orgs_per_user in
#     coordinator.toml); add colleagues once they have logged in once.
#     `coordinator org create <name> --admin <user>` on the host is the
#     escape hatch and ignores both keys.
probefleet org create lab
probefleet org members add alice --org lab --role member
#     Admins can later rename or delete it (an empty org only):
#     probefleet org rename lab2 --org lab
#     probefleet org delete --org lab2

# 3. Offer this machine's probes to the fleet. No token, no out-of-band step:
#    it reuses the session from step 2.
probefleet share

# 4. Use the fleet.
probefleet ctl list
probefleet ctl lease 'tag=nrf52'

# 5. A headless Pi in the lab: prints a URL + code; a colleague approves it
#    from a machine where they are logged in.
#      probefleet node up --fleet-url <url>       (on the Pi)
#      probefleet node approve ABCD-1234           (on their laptop)
#    Nothing long-lived is copy-pasted, and the credential is bound at
#    approval time. For an unattended image, use 5b instead.
probefleet node up --fleet-url https://fleet.example.com

# 5b. …or, for an unattended image, a pre-minted `node` API key. Mint it on
#     your laptop with the login from step 2 — no shell on the coordinator:
probefleet auth-key create --org acme --tag lab --tag nrf52 --ttl 24h
probefleet node up --auth-key prfk1_…
#     Self-hosted, or air-gapped, or for a key that never expires, the same
#     thing from a shell on the coordinator host:
probefleet coordinator auth-key --org acme --tag lab --ttl 24h
#     Same verb, same flags as the API path, for a CI key that never expires:
probefleet coordinator auth-key --org acme --tag lab --purpose ci --ttl 0

# 6. Give a colleague access to some of your boards (by their username).
probefleet grant bob --select 'tag=nrf52' --ops flash,attach --until 2026-12-31

# 7. Hand a sandboxed agent one board, with no fleet identity of its own.
probefleet ctl delegate --select 'tag=nrf52' --ops flash,attach --ttl 2h
#    → prints a lease-bound capability token; nothing else is granted.
```



### 4.2 `node` (Raspberry Pi)
Owns local probes. Reconciles discovered probes against `boards.toml`.

> **Spelling.** The canonical verbs are `node up` (bootstrap, then run) and
> `node run` (run with the credential this machine already has). The older
> `agent` / `agent up` spelling still works — same argument shapes, same role
> functions — but is hidden from `--help`, so deployed service units and
> scripts keep running while `--help` advertises one vocabulary. Note the
> `agent` **group** is itself advertised, because `agent login` (§6.7) is a
> current verb under it; what is hidden is the deprecated bare `agent` and
> `agent up`.

> **Ground truth (verified against the real probe-rs 0.31.0 source and
> re-verified line-by-line against v0.32.0):** The server is `probe-rs serve`.
> It takes **no `--probe` / `--chip`** — it exposes *all* local probes and the
> connecting client selects probe + chip **in-band**. So there is **no CLI
> injection point** for the agent. The genuine `probe-rs serve`:
>
> - **Binds TCP**, default `0.0.0.0:3000` (`TcpListener::bind`). (0.32 also has
>   an `address = "socket://<path>"` Unix-socket scheme; we deliberately keep
>   the loopback-TCP model — see *Rejected: `socket://` Unix-socket serve*
>   below.)
> - **Speaks WebSocket** at route `/worker` (axum), with **challenge/token**
>   auth (`Probe-Rs-Challenge` header; client replies `sha512(challenge||token)`).
> - Has **no `--config` flag**. `ServerConfig` is the `server` field of the
>   top-level config loaded via **Figment** from `.probe-rs.{toml,json,yaml,yml}`
>   searched in **cwd → exe dir → home**. So config lives under a **`[server]`**
>   table (`#[serde(deny_unknown_fields)]`), with `[[server.users]]` entries
>   requiring `name`, `token`, and `access` (NOT `probe_access`).
> - The client honours `PROBE_RS_REMOTE_HOST` (a **`ws://` base URL** — the
>   client appends `/worker`) and `PROBE_RS_REMOTE_TOKEN`.

Decided agent model:

- **Byte-proxy `probe-rs serve`, one server per board.** The agent spawns a
  `probe-rs serve` per board listening on a **loopback TCP port** (ephemeral,
  allocated per-board so boards never collide on serve's default `3000`), each
  locked to its physical probe via a per-user `ProbeAccess::Allow([serial])`
  under the config's `[server.users]`. The agent generates a `.probe-rs.toml`
  (Figment filename) in a per-board `current_dir` and spawns `probe-rs serve`
  there (**no `--config`**). It then byte-splices the raw **TCP stream of
  serve's `/worker` WebSocket** through the relay — **zero probe-rs / WebSocket
  parsing** (the relay stays byte-opaque; it just carries WS-over-TCP bytes).
  Per-board and **actually reused across a holder's many invocations**, recycled
  on release, fault or power-cycle. This matches time-based sharing (§6).
  - **Reuse is what the process model is for.** (A server per *channel* would
    make the second invocation against a board die in `nusb`
    with `interface is busy`, `errno 16`). Upstream `serve`'s `run_tcp` accepts
    connections in a **loop**, building a per-connection `RpcApp` over one
    shared `ProbeBroker` — the type whose job is "grant exclusive use of a probe
    to one waiter at a time, in the order the waiters arrived". Two OS
    processes cannot share that broker; one process with many connections is
    exactly what it was written for. The node's session table is therefore keyed
    by **board**, holding one process and the set of channels spliced onto it.
  - **A channel is per-invocation; the process is per-lease.** Closing a channel
    never kills the server — killing on last-channel-close would reintroduce the
    per-invocation respawn. It dies at release, expiry, fault, or a power cycle,
    and is respawned if a channel arrives under a *different* lease (new
    hardware ownership must not inherit target state).
  - **The fleet opts into the broker rather than around it.** probe-rs's
    `--attach-timeout` defaults to **zero**, which makes `attach` report
    `ProbeInUse` the instant the broker is busy instead of queueing. The sidecar
    therefore sets `PROBE_RS_ATTACH_TIMEOUT` (10s) when the caller set none, so
    a teardown still in flight, or a second legitimately concurrent channel on
    one board (§6.5 sharing, or a `ctl delegate` sandbox landing on the same
    server), *waits its turn* — the §6 time-sharing semantics — rather than
    failing. An explicit `--attach-timeout` always wins.
  - **Token wiring (end-to-end), protocol 11:** the serve user `token` in
    `.probe-rs.toml` is a **lease-scoped serve token** the coordinator mints
    (`HMAC-SHA256(signing seed, label ‖ lease ‖ board)`, hex) and carries to
    both ends — `OpenSession { serve_token }` to the node, `ChannelOpened
    { serve_token }` to the sidecar, which exports it verbatim as
    `PROBE_RS_REMOTE_TOKEN`. It is deliberately **not** the capability token any
    more: that one is per-channel and re-attenuated at every open, while a
    reused server reads its Figment config exactly once at startup, so a
    per-channel value would force a respawn per invocation. The capability token
    keeps its own job unchanged — the node verifies it, per channel, before
    doing anything (§6.5).
  - **Figment caveat:** a `.probe-rs.toml` in the agent's home dir would, by
    Figment merge order (later wins), override the per-board cwd config. The
    agent runs in a controlled environment without one.
- **Isolation comes from us, not from `serve` flags.** `ProbeAccess` per-board
  is the defense-in-depth fence so a leaseholder can only touch its own board,
  in addition to the fleet lease layer.
- **Embedding probe-rs as a library is unnecessary for v1** — the subprocess
  `serve` model is byte-compatible with any deployed probe-rs version.
- **`probe-rs gdb` / `debug` are NOT remote-capable in 0.31 or 0.32; gdb is
  tunneled as a second opaque channel.** gdb runs a separate local TCP stub
  (default `127.0.0.1:1337`), not over postcard-rpc. So the fleet runs `probe-rs gdb`
  **on the agent** (which has the physical probe) and tunnels its raw gdbremote
  TCP as a **second relay channel** (`ChannelKind::Gdb`), structurally identical
  to the data plane. On a gdb-kind `OpenSession` the agent spawns `probe-rs gdb
  --chip <C> --probe <serial> --gdb-connection-string 127.0.0.1:<ephemeral>`
  (the `gdb` subcommand, unlike `serve`, *does* take `--probe`/`--chip`), binds
  it to an ephemeral loopback port (avoiding the fixed-1337 clash when several
  boards run gdb on one Pi), connects, and byte-splices that TCP stream onto the
  channel — zero gdbremote parsing. The gdb capability is gated by the same
  capability token (`AllowedOp::Gdb`). `debug` (TUI) / `dap_server` are the same
  gap class but out of scope for v1. An upstream probe-rs feature request to make
  `gdb` drive a remote `Session` over postcard-rpc (which would obsolete this
  tunnel) is an optional follow-up. *(Post-0.32 master has since made `probe-rs
  gdb` attach through the RPC client, so this tunnel can likely be retired once
  0.33 ships — unreleased, so nothing changes yet; tracked as issue #298.)*

#### Serial passthrough (`ChannelKind::Serial`)

Most probes expose a USB CDC-ACM / USB-serial interface next to the debug
interface (ST-Link VCP, J-Link VCOM, DAPLink, ESP USB-JTAG-serial, FTDI). The
node passes it through to the lease holder as a **third relay channel kind**,
riding the same relay, lease authorization, per-channel capability token and
close-on-release / close-on-disconnect machinery as the data and gdb planes —
the coordinator gained no serial-specific logic beyond copying the port list
into its board inventory.

* **Discovery.** The node walks `/sys/class/tty/*/device` up to the first
  ancestor carrying `idVendor`/`idProduct` and associates a tty with a board
  when that USB device's serial number matches the probe serial (case-
  insensitively, or as the hex of the sysfs bytes — probe-rs hex-encodes some
  ST-Link serials) and, when known, its vid/pid. Ports are named `if<N>` by
  USB interface number. `[[board.uart]]` (§8) adds explicitly configured ports
  (a separate FTDI adapter) and `uart_discover = false` turns the automatic
  match off. The resulting `SerialPortInfo`s ride `BoardStatus.serial_ports`,
  so a tty appearing or vanishing is an inventory change reported like any
  other; `ctl list` and the web UI show the names.
* **No client paths.** The client names a *port*, never a device path; the
  node re-resolves names against a fresh tty listing at channel open
  (ttyACM numbers move on re-enumeration), so a leaseholder cannot make the
  node open an arbitrary `/dev` node.
* **In-band framing.** Each `DataFrame` on a serial channel carries exactly
  one postcard `SerialRequest` (client → node: `Open`, `Data`, `Configure`,
  `SetDtr`, `SetRts`, `Break`) or `SerialEvent` (`Opened`, `Data`, `Error`,
  `Closed`). WebSocket messages are delimited and the relay forwards frames
  1:1, so boundaries survive and the coordinator stays byte-opaque — no new
  envelope variant, no `/delegate` allowlist change.
* **Gating and lifecycle.** Opening requires `AllowedOp::Attach` (a UART is no
  more privileged than attaching). The node opens the tty exclusively
  (`serialport`, `TIOCEXCL` + `flock`) only once the client's `Open` arrives,
  one channel per port, and closes it — dropping buffered input — on
  `KillSession`, lease release, power cycle, fault, or a dropped coordinator
  connection. Serial coexists with a running `probe-rs serve`/gdb session on
  the same board: flash and watch the UART is the point.
* **Client.** `probefleet ctl serial <board>` (the board must be leased by the
  caller — e.g. the sidecar's cached lease) attaches the terminal in raw mode
  (escape `Ctrl-]`: `q` quit, `r` reset pulse, `d`/`t` toggle DTR/RTS, `b`
  break), or just pipes when stdin is not a tty (CI: `ctl serial b > uart.log
  < /dev/null`). `--pty [--link PATH]` instead exposes a pseudo-terminal
  symlinked at `$XDG_RUNTIME_DIR/probefleet/serial/<board>[-<port>]`, so
  picocom/tio/minicom/pyserial work unmodified. Baud, stop bits and flow
  control a tool sets on the pty are detected by polling the slave's termios
  and forwarded as `Configure`. Limitations: Linux ptys have no modem lines
  (DTR/RTS stay on the escape commands) and force CS8/no parity (data bits and
  parity come from the command line). FIFOs were rejected (unidirectional, no
  termios); kernel-level emulation (tty0tty, CUSE, usbip) needs root.
* **Deferred** (same channel, no wire change): an RFC 2217 server for
  DTR/RTS-capable remote clients (esptool, pyserial `rfc2217://`), and sidecar
  auto-attach (tee the UART while `probe-rs run` executes).

A node also owns **USB power** behind a `PowerControl` trait: `uhubctl` (per-hub
port), GPIO relay, or `none`. Used for post-lease cleanup and fault recovery,
and exposed explicitly via `ctl`.

#### Rejected: `socket://` Unix-socket serve (issue #297, decided)

probe-rs 0.32 added a Unix-socket server path (`[server] address =
"socket://<path>"`). It was evaluated as a replacement for the loopback-TCP
port-per-board model above and **rejected**. Verified line-by-line against the
real `probe-rs-tools` 0.32.0 sources — `src/bin/probe-rs/cmd/serve.rs`,
`rpc/client.rs`, `rpc/transport/unix.rs` — not against the changelog. Three
findings, each independently sufficient:

1. **The socket path cannot be fenced per-probe at all.** This is stronger than
   "`run_unix()` ignores `config.users`". `run_unix(self, socket_path, _config)`
   never reads the config; `handle_unix_rpc(stream)` is handed *only* the
   stream, so it could not consult it; and it builds the RPC app as
   `RpcApp::create_server(SERVER_DEPTH, ProbeAccess::All)` — the access level is
   a **hardcoded literal**. No config, no socket permissions and no filesystem
   layout can restore `ProbeAccess::Allow(["vid:pid:serial"])` on that path.
   Anything that connects drives **every probe on the Pi**. So the "equivalent
   isolation story" this swap was required to come with is not merely expensive,
   it is **unavailable in 0.32**. Today a buggy or hostile session is fenced to
   its own board; on the socket path it would reach all of them.

2. **Filesystem permissions fence the wrong population.** `run_unix` chmods the
   socket `0o660` — a fence against *other local uids on the Pi*. But a fleet
   leaseholder is not a local uid: it is a remote workstation/CI client arriving
   through the coordinator relay, and the only process that ever connects to
   `serve` is the agent itself, which byte-splices. Every board's `serve` is
   spawned by the one agent uid, so every per-board socket would carry identical
   owner and mode — **zero per-board separation**. Recovering any would mean
   spawning each `serve` under its own dedicated uid (per-Pi user provisioning,
   plus root or `CAP_SETUID` in the agent), and by finding 1 that would *still*
   not fence which probe a connection may touch. A real deployment cost buying
   nothing.

3. **It breaks the end-to-end capability-token wiring on both ends.** The two
   transports are not the same byte stream: the socket path is raw `u32-LE`
   length-prefixed postcard (`UnixStreamTx`/`UnixStreamRx`), while TCP is
   WebSocket at `/worker` behind the `Probe-Rs-Challenge` /
   `sha512(challenge||token)` handshake. §4.2's "zero protocol change" token
   story rests on that handshake. And the *client* drops the token too:
   `connect(host, token)` early-returns `connect_unix(path)` without passing it.
   So adopting `socket://` also forces the sidecar off its advertised
   `ws://127.0.0.1:<port>` endpoint, and leaves the capability token decorative
   at the probe-rs layer on **both** ends.

**What it would have bought.** Only `alloc_ephemeral_port` plus the connect-retry
that covers its bind/close race — about ten lines. Not even conceptually, since
`probe-rs gdb` independently binds an ephemeral loopback port for
`--gdb-connection-string` (`crates/probefleet-agent/src/gdb.rs`), so the agent keeps
port allocation regardless. Trading the per-board `ProbeAccess` fence and the
end-to-end token for ten lines is not a trade worth making.

**Why loopback TCP is sound.** `address = "127.0.0.1"` makes `serve` unreachable
off-Pi, and the per-board user token gates it on-Pi — an *authenticated* fence,
where the socket path offers only an ambient one.

**What would reopen this.** Upstream teaching `run_unix` to honour
`config.users` — both the `access` fence and a credential check (the challenge
handshake, or `SO_PEERCRED`). Until then, loopback TCP stands. The negative
assertions in `probers.rs`'s `rendered_config_is_server_table_with_access` pin
the decision in code.

#### Config & scaffolding (`node up`)

The node's credential lives in the **per-fleet config** (§4.1). Node-local
settings live at `~/.config/probefleet/node/` (`node.toml`, `boards.toml`)
— they describe the machine, not the fleet.

`probefleet node up` registers this machine as a node and starts serving.
It obtains a node token by whichever of these applies, in order:

1. **An existing `[node]` credential** in the fleet config — just reconnect.
2. **An existing `[user]` session** (i.e. `login` has run here) — self-register
   silently against your org. This is what `share` does; membership is
   sufficient, no admin approval (decided).
3. **Interactive approval** — print a URL + short code; a human approves from a
   machine where they are already logged in (`probefleet node approve
   ABCD-1234`). This is the headless-Pi path, and it replaces the copy-paste of
   a bootstrap token.
4. **An API key of purpose `node`** (`--auth-key`, redeemed at
   `POST /node/enroll`) — org-scoped, expiring, optionally single-use,
   carrying default tags in its payload. This is the unattended/image path.

**Rung 3 approves from the CLI or the browser.** Approval is keyed by
`user_code` and is a pure function of `(code, decision, authenticated user)`:
`probefleet node approve` and the web UI's `POST
/api/v1/nodes/pending/{code}` (session cookie, `docs/web-ui.md`) both resolve
their subject their own way and call the same `http::decide_pending_node`, with
the same membership check and the same `node.approve.*` audit rows. The
node-side wire contract (`start` / `poll`) never learns which mechanism
approved it. Three things are pinned so the browser cannot quietly make rung 3
weaker:

* **`GET /node/approve` has no form.** It is informational and reflects
  nothing — no code in the URL, no query parameter echoed — so it cannot become
  a confused-deputy surface; it links to `/ui/approve` (rewritten client-side to `/<org>/approve`),
  which is where the form
  lives.
* **There is no pending-registration listing.** A pending row's namespace is
  `NULL` until approval binds it, so a listing could only show every live
  code in the deployment: a cross-tenant index that would turn §6.4's
  "guess ~40 bits" into "read the list". Approval stays code-driven
  (`docs/web-ui.md` §3/§4).
* **The phishing warning travels with the response.** Because nothing lists
  pending rows, the approver has only what `inspect` returns; the sentence the
  CLI prints — you cannot see this machine, approve only an enrollment you
  started — is a server-sent field on that response, not frontend copy.

The cross-tenant code-enumeration risk below is the same on both paths: same
handler, same entropy, same TTL, same audit row, same "the enrolling machine
prints which org it landed in" control.
>
**The rung is gated on there being a human.** `--interactive` /
`--no-interactive`, defaulting to whether stdout is a terminal: a service unit
with no tty fails fast with remediation instead of printing a code into its
journal and blocking for fifteen minutes on nobody. It is also tried **last**
among the bootstrapping rungs, for the same reason in reverse — anything that
can succeed without a human should.

**Why rung 3 exists next to auth keys.** Rung 4's key needs no shell on the
coordinator (any member mints one), so headless enrollment works without
rung 3. What rung 3 adds: nothing long-lived is copy-pasted, and the
credential is bound at approval time rather than minted in advance and
carried around.

One **deliberate deviation** from the order above: an explicit `--auth-key`
beats an existing `[user]` session. Passing it is a deliberate act — a
provisioning script run on a developer's own laptop should enroll the node it
was told to, not the one the laptop's owner implies. An existing `[node]`
credential still wins over everything, and is reused rather than replaced.

`share` is `node up`'s rung 2 as a standalone verb, and does **not** start
the node: it writes the credential and the node-local settings, and its
summary points at `probefleet node run`.

The node token is long-lived but **rotating**: the coordinator can issue a
replacement over the established connection, so a leaked token has bounded
value and revocation is a `DELETE` in the `node` table rather than a CRL.

**Probe adoption is per-node policy, not a global gate.** Making every probe
wait for a `boards.toml` declaration is right for a lab and pure friction for a
laptop:

- `adopt = "auto"` (default for nodes created by `share`): discovered probes are
  adopted into the owning org automatically, with tags inferred from the probe.
  Plug in a board, it is usable.
- `adopt = "declared"` (default for auth-key / lab nodes): unknown probes are
  reported but not leasable until declared, so CI gets stable ids and no
  surprises.

`boards.toml` is therefore **annotation and override** — stable ids, power
wiring, curated tags — rather than admission control.

**Where the policy lives, and which copy wins.** It is recorded in two places
and they are not equals. The **coordinator's `node` row is authoritative**: it
is the enforcement point, and an adopted board reported by a node whose row says
`declared` is dropped. The node's own `node.toml` copy is *advisory* — it
governs only whether the agent bothers to synthesise board metadata for
undeclared probes at all. Editing it locally therefore does not change what the
coordinator will adopt; re-running `share` / `node up --adopt …` does. (Having
the coordinator push the policy down the established connection, as it does for
node tokens, is an obvious follow-up and deliberately not built here.)

**What an adopted board looks like.** Its id is derived from the probe alone
(`{product-slug}-{serial}`, or `probe-{vid}{pid}-{serial}` where the probe
reports no product), so it survives a restart and a reordered `probe-rs list` —
a lease selector names that id. Its tags are the probe type plus a literal
`auto`. Its `chip` is **empty** and its `model` is **absent**, because
`probe-rs list` reports the probe and neither the target attached to it nor the
board it is wired to; the honest consequence is that neither `ctl lease
chip=…` nor `ctl lease board=<model>` will match an adopted board until
`boards.toml` annotates it. Its tags can, however, be **replaced from the web
UI** (Devices → Edit tags) with a coordinator-held override that survives the
probe being unplugged and replugged — the way to make an adopted board
`tag=`-matchable without touching the machine (see §8). Two probes are never adopted: one that is `inaccessible` (the
lease would fail at `probe-rs serve` spawn time) and one reporting no serial
(which can be neither stably named nor fenced with `ProbeAccess::Allow`).

**Live discovery.** None of this means anything without a node that
re-enumerates: the agent runs a discovery pass every `discovery_secs` (default
30) and reports a new inventory **only when it changed**, so a quiet fleet stays
quiet. An enumeration failure keeps the previous inventory and does not drop the
connection — a transient USB or `probe-rs` hiccup taking every board offline
would be far worse than a stale snapshot.

**Unplugging is a report, not an absence.** A board leaves the scheduler either
via an explicit `Offline` status or by disappearing from the report entirely
(see the two-store rule below). The tombstone path exists because the second one
is coarser: it falls out for a *declared* board (its `boards.toml` entry is
still there to report as offline), but an adopted board has no declaration, so
the agent remembers what the previous pass adopted and emits an offline
tombstone for anything that has since gone. Without it an unplugged laptop board
would sit in the scheduler as `Idle` forever: `ctl list` would show it, a lease
against it would be *granted* and a capability token minted, and the agent would
refuse at the last hop. A laptop is the machine where probes are unplugged
several times a day, so this is the common path.

The tombstone is honoured whatever the node's policy currently says — removing a
board is never a tenancy risk, and a node whose policy was flipped `auto` →
`declared` must still be able to retire what it adopted while it was `auto`.

**Two stores, two meanings.** A `ProbeInventory` is a full snapshot, never a
delta, so `Coordinator::reconcile_inventory` treats it as a **set**:

- The **scheduler** is *what can be leased right now*. A board is present iff
  the latest report declares it, reports it `Online`, and policy admits it.
  `Offline`, or absent from the report → removed.
- The **`board` table** is *what the node currently declares*. A row exists iff
  the latest report carries the board and the coordinator admits it: a declared
  board at any presence, or an adopted board the policy admits online. A
  declared board reported `Offline` **keeps** its row — a probe unplugged for an
  afternoon must not vanish from the browser UI, nor churn rows every
  `discovery_secs` — but it is not leasable. A board **absent** from the report
  (renamed, or deleted from `boards.toml`) is no longer declared, so its row is
  deleted; an empty inventory clears the node's rows entirely, deliberately. An
  adopted `Offline` status is a tombstone, not a declaration, and clears both
  stores.
- A **live lease pins the board in both stores** even when the report stops
  declaring it: dropping it would strand an open lease nothing can release.
  The stale entry is retired by a later report instead.

The invariant: the DB set is the scheduler set plus declared-but-offline boards,
and nothing else. The browser UI's Agents page counts rows and Devices lists the
scheduler, so Agents ≥ Devices, and they differ *only* by unplugged declared
boards. Without the set difference, board rows would only ever be written and
never deleted, so every rename would leak a row — and, within one coordinator
lifetime, a leasable phantom.


### 4.3 `sidecar` (workstation / CI)
Presents a **vanilla probe-rs CLI surface** so laze runs unmodified. Installed
as / dispatches on a binary named `probe-rs` on `PATH` (argv0 dispatch). It:

1. Parses the probe-rs subcommand laze invoked (see §7).
2. Reads a fleet selector + token from env.
3. Asks the coordinator to lease a matching board → gets `{agent, channel,
   token, expires}`.
4. Opens a relayed data-plane channel and proxies the **regular probe-rs
   client connection** through coordinator → agent → agent's probe-rs server.
5. Streams stdout/stderr back and **propagates the exit code** (critical for
   `run` = embedded-test pass/fail and for CI).
6. Heartbeats to renew the lease for long-lived sessions (`attach`, `gdb`).
   **Implemented**: the fleet path requests the coordinator's policy-default
   TTL (`duration_secs: 0`) and heartbeats it for the whole invocation, so a
   session longer than one TTL is not swept mid-flight. It releases on
   SIGINT/SIGTERM *unless* the lease is shared with the next invocation, which
   §6.6 explains.

#### Credentials

ctl and the sidecar both read the **`[user]` session** from the per-fleet config
(§4.1) — or, in CI, a token exchanged from a workload OIDC credential. There
is no client certificate.

Resolution precedence is **explicit flag / env var > fleet config**. The
credential env var is a single `PROBEFLEET_TOKEN`. The *selector* vars
(`PROBEFLEET_BOARD` / `_ID` / `_SELECT`) are overridden by
`sidecar --board` / `--id` / `--select` (§7).

**A sandboxed agent is never given these credentials.** It receives a
lease-bound capability token instead (`ctl delegate`, §6.5).

**Both renew their own session.** Without that, a workstation whose only fleet
use is `laze` → shim → `probe-rs` would hit a 12-hour cliff regardless of how
heavily it was used. Both renew through the same `ensure_fresh_session`, using
the `[user].refresh_token` written by
`login`. That is safe on a per-invocation hot path only because redemption is
non-rotating — see §6.4's "A self-renewing user session", which also states
what that costs. Two consequences worth naming here:

* an explicit `PROBEFLEET_TOKEN` short-circuits the whole thing, since it
  wins by precedence anyway and renewing a credential we would discard is pure
  churn; and
* a renewal failure is a warning and a fall back to the stored token, never an
  error — a merely-expired token produces a better failure than a shim that
  refuses to start. A session already past `expires` with **no** refresh token
  skips the round trip entirely rather than spending a 30s timeout on a refresh
  the coordinator would definitionally refuse.


### 4.4 Shell completion (dynamic)

The binary completes its own command line. `clap_complete`'s **dynamic** engine
(`COMPLETE=<shell> probefleet`) installs a small shell stub that calls back
into the binary on every Tab; the binary answers with candidates computed *at
that moment*. `probefleet completions <shell>` prints the one line that
installs the stub.

A statically generated script was rejected: the completions that matter here
are not static. `--fleet` completes the fleets this machine has a config file
for, `ctl release` / `--id` complete the board ids in this node's
`boards.toml`, `--select` completes `id=` / `board=` / `chip=` / `tag=` and then
the local values for the prefix typed, and `--ops` completes the labels
`AllowedOp` actually defines — so adding an op cannot leave a stale script
behind. Hidden verbs (the deprecated `agent` / `agent up` node spellings, §4.2)
are not offered: Tab teaches the vocabulary, so it should teach the current one.
That cuts both ways — the `agent` group itself *is* offered, since `agent login`
(§6.7) is current; only its deprecated subcommands are suppressed.

Two constraints follow from a completer running inside a keypress, and both are
load-bearing:

* **Local state only, never the coordinator.** A completer that dialled the
  network would hang the user's terminal on an unreachable fleet. Board
  completion is therefore node-local and knowingly partial — it cannot see
  boards on other nodes or ones shared with you.
* **Every failure is an empty candidate list.** A missing, malformed or
  unreadable file yields nothing rather than an error; a diagnostic printed
  here would corrupt the completion stream. The one completer that shells out
  (`node board add --serial`, which needs `probe-rs list`) is hard-bounded by a
  short timeout.

The completion hook runs **before** logging, the runtime, and any write to
stdout, and only on the clap path: invoked as `probe-rs`, the binary forwards
argv verbatim to the real probe-rs (§4.3), so those words are not ours to
complete.


## 5. The dial-out connection (NAT traversal)

The node opens **one persistent WSS connection out** to the coordinator
(`GET /agent`, `Authorization: Bearer <node token>`) and holds it. All
coordinator→node commands travel back down that same connection, so the Pis need
**no inbound ports**. Ping/pong keepalive holds it open through the reverse
proxy (§3.5). Over this connection:

- agent → coordinator: register, report inventory, heartbeat, emit
  faults/logs/power events.
- coordinator → node: "open a probe-rs session to board X for lease L",
  "power-cycle board X", "kill session", "what's your state", "here is your
  rotated node token".
- a **leased opaque channel** carries the data plane (probe-rs postcard-rpc
  frames — flash bytes, RTT) multiplexed alongside the small control RPCs.

The server→client direction rides the same WebSocket: the coordinator writes
command frames down the node's dial-out connection, multiplexed with the opaque
data channel by the `probefleet-wire` envelopes.

## 6. Identity, auth & leases (on forgs)

Authentication is by bearer token, user identity is rooted in a login provider,
and there is an authorization layer over every board. Every generic piece of
that — users, orgs, memberships, sessions, refresh tokens, API keys, workload
tokens, grants, the device flow, browser login, cookies and CSRF — lives in
**forgs** ([github.com/kaspar030/forgs](https://github.com/kaspar030/forgs),
`docs/design.md` there), a crates.io dependency of this workspace. fleet keeps only
what is about hardware: nodes, boards, leases, capability tokens, the board
selector and op vocabulary, and the two hooks through which forgs asks fleet a
question.

fleet's own schema is a single `0001_fleet.sql` holding its tables; there is
no migration from databases that predate forgs, so such a deployment starts
fresh (every user logs in again and every node re-enrolls).

### 6.1 Identity model

The fleet is **multi-tenant**. Every hardware object belongs to an org; every
user request acts within one org it names.

forgs owns the identity tables (all prefixed `forgs_`, created by
`forgs_store::migrate` before fleet's own migrator runs, in the same SQLite
file). fleet's tables hold real foreign keys into them:

```
-- forgs (generic)
forgs_user      { id (ULID), username UNIQUE, … }
forgs_identity  { user_id, provider, provider_subject, email, email_verified }
                  UNIQUE (provider, provider_subject)
forgs_ns_node   { id (ULID), parent_id NULL, kind = 'org', name, … }
forgs_membership{ ns_node_id, user_id, role: member | admin }
forgs_grant     { id (ULID), ns_node_id, subject, selector, ops, expires, created_by }
forgs_api_key   { ns_node_id, key_hash, purpose, payload, single_use, expires,
                  created_by, subject_name? }
forgs_session / forgs_refresh_token / forgs_workload_token / forgs_pending_device /
forgs_audit / …

-- fleet (crates/probefleet-coordinator/migrations/0001_fleet.sql)
node      { id "<org id>/<name>", ns_node_id → forgs_ns_node,
            owner_user_id → forgs_user NULL, name, tags, token_hash,
            token_issued_at, adopt_policy, last_seen }   UNIQUE (ns_node_id, name)
board     { ns_node_id, node_id → node, name, chip, model, tags, … }
board_tag_override { ns_node_id, node_id → node, name, tags, updated_by,
            updated_at }   -- 0002; UI-set tags, no FK to board (outlives a prune)
leases    { lease, ns_node_id, node_id, board_name, holder (subject key), … }
audit_log { ts, ns_node_id NOT NULL, subject, action, node_id, board, lease, detail }
```

The decisions that are load-bearing:

- **Ids are immutable ULIDs; names are handles.** A user is `user:<ULID>`, an
  org is a `forgs_ns_node` ULID. Usernames and org names can be renamed; every
  stored reference (membership, grant, node, lease, audit row) is an id, and a
  handle is resolved to an id **once**, where the reference is written (e.g.
  `grant bob …` resolves `bob` at grant creation). A released name is
  tombstoned forever, so a rename cannot hand the old path to a squatter.
  `OrgId` in `probefleet-proto` carries the ns-node ULID text.
- **A login provider proves who you are; it does not name you.** Providers
  (GitHub, Codeberg/Forgejo, GitLab, generic OIDC — §6.4) supply
  `(provider, immutable subject id, verified email)`. The identity is keyed on
  `(provider, provider_subject)` — for GitHub the numeric user id — **never**
  on the login or the email, both of which get reassigned. The **username is
  chosen by the user at first login** (forgs signup); the provider's login is
  offered only as a suggestion.
- **One namespace kind, `org`, at the root; everyone has a personal one.**
  fleet's forgs schema is
  `Schema::builder().kind("org", KindSpec::root().personal_for_users())`.
  Signup creates the user's personal org, named like the username, with the
  user as `admin`, in the same transaction. Team orgs sit beside personal ones
  in the same root name space (so a user and an org cannot share a name).
  Any logged-in user can create one — `probefleet org create <name>` or
  the web UI's Org page (`POST /api/v1/orgs`) — and becomes its admin; the
  creation is audited as `org.create` in the new org. Two coordinator.toml
  keys gate it: `allow_org_creation` (default `true`; `false` → `403
  org_creation_disabled`) and `max_orgs_per_user` (default `10`, `0` =
  unlimited; counts team orgs the user created; a hard cap, checked in the
  creating transaction by forgs' `create_namespace` → `403
  org_limit_reached`). A name colliding with an org, a username or
  a tombstoned name is `409 name_taken`. `coordinator org create <name>
  --admin <username>` stays as the host-shell escape hatch and ignores both
  keys. Admins manage members with `probefleet org members
  add|set-role|remove` (forgs' `/auth/members`) or the web UI
  (`forgs_http::members::{set,remove}`, audited `member.set` /
  `member.remove`); removing or demoting the last admin is `409 last_admin`.
  Admins rename a team org with `probefleet org rename <new>` or the web
  UI (`POST /api/v1/org/rename`, audited `org.rename`; the old name is
  tombstoned) and delete one with `probefleet org delete` (`DELETE
  /api/v1/org`, audited `org.delete`). Personal orgs are refused (`409
  personal_org`); delete is refused while nodes, boards, open leases or live
  grants reference the org (`409 org_not_empty`), and purges the org's closed
  leases and fleet audit log, which would otherwise block it (`ON DELETE
  RESTRICT`). Invites and join requests are follow-ups. The
  config's `default_org` is an org **name** the coordinator ensures exists at
  startup; it is consulted only by operator verbs, never by an authenticated
  request. There is still no user-owned/org-owned branch: one scoping rule
  everywhere.
- **Reserved names**, enforced by forgs at every creation path (signup,
  rename, org create, `default_org`): `gha`, `api`, `auth`, `ui`, `admin`,
  `login`, `system`, `node`, `agent`, `client`, `delegate`, `healthz`
  (`state.rs::RESERVED_NAMES`). `gha` matters most: it is the namespace
  segment of GitHub Actions workload subjects (§6.7), and no tenant may ever
  be named that.
- **Roles are a two-rung ladder, `member < admin`**
  (`RoleLadder::new(&["member","admin"])`, `subject::FleetRole`). Membership
  is enough to add a node, use the org's boards and mint an API key; admin is
  needed to create grants, read the audit log, manage members and act on
  others' objects.
- **The acting org is chosen per request.** A session is not bound to one org
  at mint time. A user request names its org — `/client?org=<path or
  id>`, `/api/v1/…?org=`, an `org` field in `SelfRegister` /
  `NodeApprovalRequest`, `--org` on the CLI — defaulting to the user's
  personal org, and membership is checked there (`http::acting_subject`). An
  org you are not a member of and one that does not exist are the same `403`.
  A node acts in its node row's org; a workload acts in **none** and reaches
  boards only through grants.
- **Boards are keyed `(org, node, name)`**, and a node id is already
  org-namespaced (`state.rs::node_id_for` → `"<org id>/<name>"`), so the same
  machine name in two tenants is two nodes.
- **Moving a node to another org** (`probefleet node move`, the Agents
  page's *Move…*; `Coordinator::move_node_core`) therefore changes the node's
  id. Admin of the source and member of the target are required. Leased
  boards refuse the move unless forced (then the leases are revoked). The
  node and board rows are re-keyed in one transaction (`Db::move_node`, FK
  checks deferred to commit); closed leases and audit rows stay with the
  source org. The **token survives** — it is looked up by hash, and the hash
  stays on the row — so the agent need not re-enroll; its live connection is
  closed, it reconnects, and its re-reported inventory lands in the new org.
  Its fleet file still holds the old id until its next `node up`, so
  `Register` accepts a claimed id with the same node-local name under a
  different org prefix (logged at debug, not audited). Grants are untouched:
  selectors name neither org nor node, so source-org grants simply stop
  covering the boards and target-org grants may start to; the move reports
  both lists. A single board cannot be moved.
- **Subjects.** forgs builds a `forgs::Subject` from a credential;
  `probefleet-proto::ids::SubjectKey` is its wire mirror and renders identically,
  `[<ns>/]<kind>:<id>`:

  | kind | key | from |
  |---|---|---|
  | user | `user:<ULID>` | session token |
  | node | `<org id>/node:<node id>` | node token (fleet's app kind) |
  | workload | `gha/workload:<owner>/<repo>` | GitHub Actions OIDC (§6.7) |
  | workload | `<org id>/workload:key:<hash8>` | unnamed `ci` API key |
  | workload | `<org id>/workload:agent:<name>` | `ci` key minted `--name <name>` |

  The coordinator attaches the acting org to it (`subject::Subject`) and
  converts forgs ↔ wire keys by render + parse; a key that does not survive
  the round trip is dropped closed. Lease holders on the wire and in the
  `leases` table are these keys.

**A note on test fixtures.** Domain identifiers in tests are built with the
production constructor, at the layer that would actually build them — users
via `create_local_user`, orgs via forgs' `create_node`, a node id via
`state.rs::node_id_for` — never a hand-rolled `format!("{org}/{name}")` or a
literal id. A fixture that spells an identifier itself is a second,
unversioned definition of that identifier, and it drifts: the coordinator's
board fixture once built bare node ids (`node-a`) where production built
org-qualified ones for long enough that every qualified-name resolution test
passed while addressing boards the fleet cannot produce. The rule is
*construct it the way the producing side does*, not "always prefix": an agent
genuinely does not know its own org, so the `BoardName` it mints is correctly
unprefixed. Where the constructor is out of reach — the agent crate does not
depend on the coordinator — the fixture names the shape in one documented
constant rather than repeating a literal.

### 6.2 Connection auth: bearer tokens

**There is no private CA and no mTLS** — no client CA, CSR signing, client
cert pinning or `agent_pins` table. Under bearer tokens revocation is a row
delete, which a CA never offered.

Every credential is a **prefix-typed opaque token**, minted by forgs'
`TokenFormat` with fleet's brand `prf` plus one app kind:

| Token | Prefix | Kind | Lifetime | Revocation |
|---|---|---|---|---|
| session (user) | `prfs1_` | connection | `session_ttl_secs`, default 12h | `logout`, or expiry |
| refresh (user, CLI only) | `prfr1_` | redeem-only | `refresh_token_ttl_secs`, default 30d | `logout` (`--all`), or expiry |
| API key | `prfk1_` | redeem-only | ≤ 30d over the API; a shell may mint a forever-key | `auth-key revoke` |
| workload (CI) | `prfw1_` | connection | one job: default 1h, capped at 12h, **no refresh** | expiry, or revoking the grant |
| device secret | `prfd1_` | redeem-only | the pending-approval TTL | consumed once |
| **node** | **`prfn1_`** | connection (fleet's app kind `node`, tag `n`) | long-lived, auto-rotating | delete / rotate the node row |

forgs stores only SHA-256 hashes of secrets, shows a secret once, redacts
them in `Debug`, and logs an 8-hex hash prefix. A redeem-only kind is refused
**from its prefix alone, before any database access**, and each route names
the kinds it admits (`authenticate_request(…, allowed: &[TokenKind], …)`); a
wrong kind is a `403`. So `/agent` admits node tokens only, `/client` session
or workload, `/api/v1` session only, and a refresh token or API key opens
nothing but the exchange that redeems it.

**Node tokens are fleet's, verified through forgs' seam.** forgs knows the
kind's prefix; the lookup is fleet's `tokens::NodeTokens`, an
`AppTokenLookup` over `node.token_hash` that answers the subject
`<org id>/node:<node id>`. The org comes from the node **row**, which is what
stops a node token being replayed into another tenant. Node tokens rotate over
the node's WebSocket (`node_token_rotate_secs`).

**There is exactly one place a credential becomes a subject:**
`forgs_http::authenticate_request` (and its `Authenticated` extractor).
fleet's handlers call it and then resolve the acting org; nothing in fleet
parses a bearer into a subject on its own. The one authenticated route that
builds **no** subject is `/delegate`, which verifies a capability token
instead (§6.5).

The cost, stated honestly: bearer tokens are pure bearer credentials, so a
leak is immediately usable. Short sessions, rotating node tokens and per-job
workload tokens bound the window; the refresh token is the deliberate
exception (§6.4).

**One extra carrier for the user token (`docs/web-ui.md` D1).** A browser
cannot hold an `Authorization` header the way `ctl` does, so the session token
also travels in a `prfs_session` cookie — `HttpOnly`, `Secure`
(unconditionally), `SameSite=Lax`, `Path=/`, `Max-Age` tracking the session's
expiry. This is a **second carrier of the same credential, not a second
credential kind**: the same `prfs1_` string, resolved by the same
`authenticate_request`. What the carrier changes is where it is accepted and
what else must be proven:

* it is accepted **only under `/api/v1/`** (forgs' `Carrier::ApiCookie` with
  fleet's `cookie_api_prefix`), plus forgs' own explicitly marked browser
  pages (`/auth/device`, `/auth/session/logout`, …). It is refused on
  `/agent`, `/client`, `/delegate` and the JSON `/auth/*` routes, because a
  cookie is ambient; a header, when present, wins over the cookie;
* a mutating call carrying it must also carry `X-Fleet-Csrf`, a double-submit
  token `hex(HMAC-SHA256(k_csrf, session_token_hash))` also set as the
  non-`HttpOnly` `prfs_csrf` cookie. Nothing is stored. The key comes from a
  **dedicated injected secret** (`csrf_secret_path`, ≥ 32 bytes, written as
  `csrf.secret` by `coordinator init`), domain-separated by the app label
  `probefleet`. It is **not derived from the capability-signing
  seed**: one secret per job, so rotating either does not silently rotate the
  other. A bearer-authenticated `/api/v1` call needs no CSRF header;
* no route emits CORS headers, which makes the mandatory custom header a
  second, independent control.

`HttpOnly` costs the CSRF machinery and buys that one XSS cannot walk away
with a credential that can power-cycle real hardware; `Authorization: Bearer`
from JavaScript was rejected for exactly that reason (`docs/web-ui.md` §5).

### 6.3 Capability tokens

The coordinator mints an ed25519-signed `CapabilityToken { lease, board,
allowed_ops, expires }` per lease; the node verifies the signature **locally**
with the coordinator's public key, so there is no per-operation round trip.
This is orthogonal to connection auth and did not move to forgs: it is the
attenuated, lease-bound, expiring credential the sandboxed-agent story needs
(§6.5). Its seed (`signing.seed`) signs only capability tokens and derives
the serve token; it keys nothing else.

### 6.4 Bootstrapping: one ceremony, several flavours

Enrollment is **user-rooted**: a human authenticates once, and every other
credential is derived from that authority.

| Principal | Bootstrap | Ceremony |
|---|---|---|
| **User**, browser | `/auth/login` → any configured provider (authorization-code flow) | browser |
| **User**, CLI (`login`) | forgs' own device flow: a code confirmed in a browser logged in with any provider | browser, once |
| **Node, user present** | `share` → `POST /node/self-register` with the session | zero extra steps |
| **Node, headless** | `node up` prints a URL + code; a member runs `node approve <code>` (or `/<org>/approve`) | no token copy-paste |
| **Node, unattended** | an API key of purpose `node` redeemed at `POST /node/enroll` | one paste, revocable |
| **CI worker** | GH Actions workload OIDC exchanged at `POST /auth/token`, plus a per-repo grant (§6.7) | zero secrets |
| **CI worker, no workload identity** | an API key of purpose `ci` redeemed at `POST /auth/token` (§6.7, the weak path) | one paste, revocable |
| **Sandboxed agent** | *no enrollment* — lease-bound capability token | one command |

#### Login providers, and choosing a username

Providers are **configured**, not hardcoded:

```toml
[[auth.providers]]
kind = "github"              # github | codeberg | gitlab | oidc
name = "github"              # instance name; appears in /auth/{name}/start
client_id = "…"
client_secret_path = "…"     # required: GitHub ignores PKCE
# issuer = "https://…"       # oidc (required); codeberg/gitlab override; GHES origin
```

Two instances of the same software are two providers whose subject ids never
mix. GitHub is OAuth2-only: forgs requests `read:user user:email`, reads
`GET /user/emails` and takes the `primary && verified` address. Codeberg /
Forgejo, GitLab and generic OIDC are OIDC (discovery, `id_token`,
`email_verified`). **Login without a verified email is refused**
(`no_verified_email`). The provider's access token is spent once and never
stored or logged. An empty provider list is a supported (air-gapped /
development) deployment: users are then created with `coordinator user-token
--username X`, which goes through forgs' `create_local_user` — the same code
path, minus an identity row.

The browser flow (all forgs routes, merged into fleet's router):

```
GET /auth/login  (or GET /auth/providers → JSON)  → pick a provider
GET /auth/{p}/start       → 302 to the provider; state in a sealed HttpOnly flow cookie
GET /auth/{p}/callback    → identity known?  yes → session cookies, 302 return_to (default /)
                                             no  → pending signup (sealed ticket cookie)
GET/POST /auth/signup     → choose a username (policy + reserved names + tombstones)
                          → ONE transaction: user, identity, email, personal org,
                            admin membership → session
```

* `redirect_uri` is derived from the configured `public_url` **only**, never
  from `Host` / `X-Forwarded-Host`: behind the reverse proxy a Host-derived
  callback is a host-header injection into an attacker-chosen OAuth redirect.
* `state` is bound to a sealed `HttpOnly` flow cookie. PKCE is sent but GitHub
  ignores it, so the `client_secret` is what makes an intercepted code
  unspendable; do not call this "PKCE-protected".
* **No auto-linking on email.** A new identity whose verified email matches an
  existing user is refused (`email_in_use`), not linked: auto-linking turns
  "an attacker controls a provider that asserts your email" into account
  takeover. A second login method is linked only from an authenticated
  session (`POST /auth/identities/link/{provider}`).

#### CLI login is forgs' own device flow

fleet does not broker a provider's device flow (not every provider has one).
forgs is itself the device authorization server:

```
CLI  POST /auth/device/start → { device_secret (prfd1_), user_code, verification_uri }
user opens verification_uri → logs in with ANY provider (incl. first-login signup)
     → confirms the user code on /auth/device
CLI  POST /auth/device/poll { device_secret } → pending | session + refresh + username
```

The CLI stores `session_token`, `refresh_token` and `username` in the fleet
file's `[user]` table. The one requirement is a browser-reachable
`public_url`. Accepted risks, recorded rather than fixed (there is still no
rate limiting): **remote phishing** (RFC 8628 §5.4 — an attacker talks a
victim into confirming their code; the verification page never approves from
a link alone), and **unauthenticated growth** — `start` writes a row. CLI
login and node registration share one pending table and one cap
(`max_pending_nodes`, default 256) and TTL (`pending_node_ttl_secs`); a full
table refuses new logins and enrollments until rows age out.

#### Interactive node approval

`node up` rung 3 (§4.2) reuses forgs' generic **pending-approval machine** for a
machine rather than a human. `POST /node/register/start` stores a pending row
whose JSON payload is the requested `{node_name, tags, adopt}` (charset-validated
before it is stored, since it is unauthenticated and rendered to a human); the
machine prints a ~40-bit Crockford-base32 `user_code` (`ABCD-1234`) and polls
`/node/register/poll` with its device secret. A member runs `probefleet
node approve ABCD-1234 [--org O]` (or uses `/<org>/approve`), which calls
`/node/register/approve` → forgs' `decide`, binding the row to the approver
and the chosen org. fleet's `PendingApprovalHook` (`identity::FleetNodeApprovals`)
is where fleet's policy lives:

- **authorize**: membership in the target org is sufficient, as it is to
  `share`; the node is owned by the approver (`node.owner_user_id`);
- **redeem**: the machine's next poll registers the node and mints its
  `prfn1_` token through the same `register_node_and_mint` every enrollment
  path uses, so the resulting row is identical.

Three decisions and three accepted risks:

- **Approval is a CLI verb and a browser form** (`POST /api/v1/nodes/pending/{code}`
  calls the same `http::decide_pending_node`). `GET /node/approve` stays
  informational and **reflects nothing** — no code in the URL, no query
  parameter echoed — so it cannot become a confused-deputy surface. Please do
  not "finish the job" by putting the form there.
- **There is no listing of pending registrations**: a row's namespace is
  `NULL` until approval binds it, so a listing could only be a cross-tenant
  index of every live code. The phishing warning therefore rides on the
  `inspect` response, the only thing the approver sees.
- **Approval refuses to take over an existing node.** The machine chooses its
  `node_name` before any org is known, so approving a name the org already
  uses would re-credential a running machine. The handler (not just the CLI)
  refuses with `409 node_name_taken` unless `replace` is set.
- *Risk:* **remote phishing**, sharper than for login — the approver grants
  hardware access to a machine they cannot see. `node approve` inspects first
  and prints name, tags, adoption policy, source IP and age, says to approve
  only an enrollment you started, defaults to **no**, refuses a non-tty; every
  printed field is validated server-side and neutered client-side.
- *Risk:* **cross-tenant code enumeration** — a member who guesses a live code
  can approve it into their own org. Bounded by ~40 bits behind a short TTL,
  by every attempt being audited, and by the enrolling machine printing which
  org it landed in.
- *Risk:* **unauthenticated row growth**, bounded by the shared cap above.

#### API keys (`auth-key`)

The unattended paths redeem a forgs **API key** (`prfk1_`). A key belongs to
one org, has a `purpose` and an app-defined `payload`, and fleet's
`ApiKeyPurposes` (`identity::FleetPurposes`) defines two purposes:

| purpose | redeemed at | payload | yields |
|---|---|---|---|
| `node` | `POST /node/enroll {auth_key, node_name}` (fleet) | `{"tags":[…]}` — stamped on every node it enrolls | a node token |
| `ci` | `POST /auth/token`, `grant_type: api_key` (forgs) | `{"tags":[…], "ops":[…]}` — the synthesised grant's selector and ops | a workload token (§6.7) |

`check_payload` validates and canonicalises the payload at mint time; a
payload that no longer forms a selector at redemption is refused, never
widened. The rules, all enforced by forgs' `/auth/keys` (and by
`/api/v1/auth-keys`, which calls the same functions):

- **Membership is sufficient to mint and to list.** The key's org is a
  *target* (`--org`, default the personal org) checked for membership, so a
  key can never exceed the caller's own access; "not a member" and "no such
  org" are the same `403`.
- **Keys minted over the API must expire**, capped at 30 days
  (`Ttls::api_key_max`); `ttl_secs = 0` is refused, not silently capped. A
  never-expiring key is an operator's informed choice from a shell on the
  coordinator host (`coordinator auth-key --ttl 0`).
- **Revocation is creator-or-admin**, by hash prefix of ≥ 8 hex characters;
  an ambiguous prefix is a `409` that deletes nothing. Revoking a `ci` key
  cascades into its grant (§6.7).

#### A self-renewing user session (`login` + refresh tokens)

A session lives `session_ttl_secs` (12h). The `probe-rs` shim, `ctl`, `share`
and friends renew it with `ensure_fresh_session` from the `[user]
refresh_token` (`POST /auth/token`, `grant_type: refresh_token`), so a
workstation whose only fleet use is `laze` → shim → `probe-rs` does not hit
a 12-hour cliff.

- **What it can do:** mint session tokens for its user. **What it cannot:**
  open `/agent`, `/client` or `/delegate`, reach `/api/v1`, mint keys, approve
  or enroll anything. It is refused from its prefix before any database
  access, and no route admits it.
- **fleet/forgs-issued, never the provider's.** Storing a GitHub access token
  would make the fleet a custodian of a credential it cannot revoke, and would
  not exist for other providers.
- **Redemption does not rotate — the load-bearing choice.** Two concurrent
  `probe-rs` invocations would race a rotating token and one would hold a
  revoked credential mid-build. A non-rotating token lets N concurrent
  redemptions all succeed. **The cost:** a leaked refresh token is usable for
  its whole TTL (30 days), with no reuse detection; it is bounded only by the
  TTL and by revocation.
- **Revocation:** `probefleet logout` → `POST /auth/logout` deletes the
  presented session and its refresh token; `--all` deletes every session and
  refresh token of the user, on every machine — the lost-machine answer.
- **CLI only.** Refresh tokens come from the device flow and `coordinator
  user-token`; the browser path issues none (`docs/web-ui.md` D1).

#### The laptop dual-role case

A laptop is routinely both a user and a node:

- **Config is per fleet, not per role** (§4.1) — one file, an optional
  `[user]` table and an optional `[node]` table.
- **The node is owned by the user** (`node.owner_user_id`), so "my laptop's
  boards" is expressible.
- **The two credentials stay distinct.** The node token is machine-scoped and
  long-lived; the session is human-scoped and short-lived. Merging them would
  make a compromised Pi equivalent to a compromised you.
- **One command:** `probefleet share` → `POST /node/self-register`, in the
  org named by `--org` (default: personal). Membership there is *checked*; a
  non-member is a `403`.

#### Security properties carried over

The switch was a move, not a rewrite; these properties (forgs
`docs/fleet-survey.md` §5.4) hold on the new code and should not be "fixed":

* identity keyed on the immutable provider subject, never a login or email;
  handles resolved to ids once, where a reference is stored;
* everyone is always in an org; a personal org of one, user admin of it;
* tenancy by type (`OrgDb` binds the org for every fleet table; forgs'
  `NsScope` likewise), foreign keys on, provisioning in one transaction; the
  few deliberately unscoped queries (grants by subject, pre-approval pending
  rows, tenant-less workload tokens) are documented as such;
* only SHA-256 hashes of secrets stored, secrets shown once, revocation is a
  row delete;
* prefix-typed tokens, redeem-only kinds refused before DB access, per-route
  allowed kinds, wrong kind → `403`;
* no oracle: one coarse error body, detail only in the audit log, cross-org
  indistinguishable from not-found;
* fail closed on DB errors and unparseable rows (grants, subjects, roles,
  payloads);
* browser: `HttpOnly` + unconditional `Secure` + `SameSite=Lax` cookie
  carrying the same session token, accepted only under `/api/v1/`,
  double-submit CSRF plus mandatory header, no CORS, no bearer in JS, strict
  CSP;
* `redirect_uri` from `public_url` only; `state` in a sealed cookie; not
  "PKCE-protected";
* OIDC: pinned `RS256`, mandatory `kid`, explicit audience, injected clock;
  trust per exact repo, never owner; one shared lowercase normaliser;
* API keys: membership to mint, must expire over the API, creator-or-admin
  revoke, prefix ≥ 8 hex, ambiguous `409`; a named identity survives rotation;
* reserved names enforced at every creation path;
* attacker-controlled strings charset-validated server-side and rendered as
  text; approval inspects first and refuses takeover without `replace`;
* grants: admin to create, must expire (≤ 365 days), namespace fence in every
  check, canonical selector stored.

### 6.5 Authorization

Authentication alone is not enough: without an authorization layer, any holder
of any valid credential could open a channel on **another subject's lease**,
extend or release anyone's lease, power-cycle any board, and read the entire
audit log. The subject model closes all of these.

The model, deliberately minimal:

- **Deny by default.** Every request resolves to a `Subject` and is checked
  against the target object's org before anything else.
- **Two roles per org**, `admin` and `member`. Membership alone is enough to add
  a node, to use the org's boards, and to mint an org-scoped auth key (decided;
  finer roles can come later without a data migration).
- **Ownership checks**, unconditionally: a lease may be extended, released, or
  channel-opened only by its holder (or an org admin). **API-key revocation
  follows the same rule** (§6.4): the creator, or an org admin — the latter
  also covering keys minted from a shell, which have no recorded creator.
- **Grants** carry sharing. They are forgs grant rows (`forgs_grant { ns,
  subject, selector, ops, expires, created_by }`): forgs stores them and
  evaluates liveness, the subject and the namespace fence, while the
  **selector** is fleet's `Constraint` rendered as canonical text and the
  **ops** are newline-joined `AllowedOp` labels — payloads forgs treats as
  opaque. The selector is the existing tag/chip constraint language. `grant bob --select
  'tag=nrf52' --ops flash,attach` is the "give access to other people" path, and
  it is revocable and audited. Individual-board grants are a degenerate
  selector.
- **Delegation to a sandbox** is *not* a grant and creates no principal:
  `ctl delegate` leases a board as you and hands out only the **capability
  token** for that lease — narrow, expiring, revocable by releasing the lease.
  The crypto is the capability token of §6.3.

#### Grants, ACL evaluation, `ctl delegate`

**One selector grammar, one reading of every term.** `id=<name>`,
`board=<model>`, `chip=<c>`, `tag=<t>`, and `a && b` conjunctions of tags,
parsed by a single function in `probefleet-proto`. The sidecar's
`PROBEFLEET_SELECT`, `ctl lease <sel>`, `ctl delegate --select` and
`grant --select` are thin delegates with **no per-surface dialect**: a bare word
is a *tag* everywhere (so `ctl lease nrf52840-dk-3` is a tag selector and the
board is named `ctl lease id=nrf52840-dk-3`).

The word "board" means the board **model** — the board type a developer asks
for ("I need an nrf52840dk") — on every surface: the `board=` term, the
`sidecar --board` flag and `PROBEFLEET_BOARD`. It is *not* the chip: a
Nordic DK and a custom nRF52840 board share `nRF52840_xxAA` and are not
interchangeable. The model is declared per board in `boards.toml`; the agent
cannot infer it, so a board with no declared model (in particular every
auto-adopted one) is never matched by `board=`. `id=<name>` is the
individual-board grant: a degenerate selector, not a special case.
`id=`/`board=`/`chip=` are not conjoinable — the wire `Constraint` has no
representation for it, and dropping the extra terms would widen a grant.

A grant stores the **canonical
rendering** (`Constraint`'s `Display`) and evaluation re-parses it, so a grant's
meaning never depends on which CLI wrote it; a row that will not re-parse is
dropped **closed**, never widened into a match-anything. An empty expression is
refused at every entry point, because an empty tag set matches every board.

There is deliberately **no wildcard**: `Constraint` has no any-board variant, and
a delegation could not express one anyway, since a `CapabilityToken` binds one
`BoardRef`. So a term made only of glob/regex metacharacters (`*`, `?`, `%`,
`.*`) is refused at parse time with a message that names the real answer — tag
the boards and select the tag (`--select lab`); `ctl list` shows what you can
reach — instead of parsing into a tag nothing carries and surfacing as a message
about board contention. Tag values are otherwise free-form: general charset
validation was declined because `boards.toml` tags are unvalidated agent-side, so
such a rule would reject working configs at selection time, far from the file.
Tags set from the web UI (a coordinator-side override that replaces a board's
reported tags, §8) *are* charset-validated, since they never pass through the
file. A CI auth key's tags *are* charset-validated at mint, since redemption turns them
into a selector.

**Evaluation is a pure value object** (`probefleet_core::access::Access`): ownership
(a member of the board's org) or a live grant, deny by default, with `now`
always a parameter — so the whole (subject, object, op) matrix is a
table-driven unit test. `Access { member_of: Vec<OrgId>, grants }` is built
per request from the user's forgs memberships plus `grants_for_subject`
mapped to fleet `GrantScope`s; a grant row whose selector or ops will not
re-parse is dropped **closed**. Ownership is `board.org ∈ member_of` (a session
is not bound to one org). The tenancy fence is not weakened by that:
board matching is org-blind, and the org comparison lives in
exactly one place, `grant.org == board.id.org` — forgs' namespace fence. A
grant issued in org A saying `tag=nrf52` therefore cannot reach org C's
identically tagged board.

**Grants attenuate the capability token.** The token minted for a lease carries
the grantee's effective ops, recomputed at every mint (lease and each channel
open) and never cached, so a narrowed or revoked grant bites on the next
channel open rather than at the end of the lease's TTL.

**What `--ops` actually enforces**, stated plainly because writing "the agent
enforces `--ops`" would be false for half the labels:

| op | enforced where |
|---|---|
| `attach` | agent, at data-channel and serial-channel open |
| `gdb` | agent, at gdb-channel open |
| `power-cycle` | coordinator, in the power-cycle handler |
| `flash`, `erase`, `reset` | **not enforced** — in-band probe-rs RPC inside the data channel, which the fleet relays without parsing |

Recording the unenforced three is intent and audit. Enforcing them would mean
the agent parsing probe-rs postcard-rpc frames; deliberately out of scope, filed
as a follow-up. One consequence is handled rather than left as a trap: a
data-plane op **implies `attach`**, because a token with `flash` but not
`attach` cannot open a data channel at all and so cannot flash. The CLI says
when the implication fires, and refuses an empty op set — a security verb must
not silently mint a dud.

**Creating a grant requires `admin`; listing needs only membership.** A
deliberate divergence from API keys, where membership is enough to
mint. The two verbs have different blast radii: an API key cannot exceed the
caller's own org, while a grant points *outward*, handing the org's hardware to
someone who is not in it at all. In a personal org you are the admin, so the
single-user story is unchanged. Grants must expire, at most 365 days out
(`Coordinator::MAX_GRANT_TTL_SECS`; the API refuses an unbounded one),
mirroring the API-key TTL discipline: an unbounded share of somebody
else's hardware is exactly the artefact that outlives its reason.

**Grantees are named by handle and stored by id.** `grant <grantee>` resolves,
in order (`core.rs::resolve_grantee`): `repo:<owner>/<name>` → the workload key
`gha/workload:<owner>/<name>` (§6.7); a rendered subject key (`user:01J…`,
`<org id>/node:…`, `<org id>/workload:agent:builder`); otherwise a **username**,
looked up once and stored as `user:<ULID>`, so the grant survives a rename and
never follows a reused name. An unknown name is `no such user \`x\``. There is no
GitHub-login lookup any more. Grant ids are forgs ULIDs; `grant revoke` takes a
prefix of at least 8 characters of one.

**Revocation is creator-or-admin, and it is real.** The rule matches API-key
revocation verbatim, including the `grant.revoke.denied` audit. Deleting the row
is not enough — it would leave the grantee relaying bytes until the lease's TTL
ran out — so revocation recomputes the grantee's access and, for every lease it
holds on a board it may no longer use, goes through the *whole* release path:
channels torn down, lease closed and audited, any promoted waiter persisted. It also
**refreshes** the grantee's queued requests — a scheduler `Waiter` holds an
access snapshot that cannot notice a revocation, so the new access is pushed in
and promotion re-decides per board. Refreshing rather than dropping matters:
cancelling all of a subject's pending requests would silently kill ones for
boards in *their own org*, collateral damage across a tenancy boundary suffered
by someone who did nothing wrong, and would also be wrong for a subject still
covered by a second overlapping grant. **Note the contrast with §6.6's
drop-on-disconnect rule**, which drops a connection's queued requests outright:
there the caller is provably gone and no promotion could reach it; here the
caller is present and only its reach changed. Same queue, opposite answers, and
neither reason generalises to the other case. The honest limit: an
already-minted
capability token stays cryptographically valid until it expires; tearing down
the relay is what makes it useless, since there is no path to the board without
the coordinator. Delegation has exactly the same bound, which is why lease TTLs
are short.

**A grantee has no "what am I granted?" verb.** `grant list` names this org's
*outbound* grants; the grantee-facing view is `ctl list`, which shows granted
boards alongside their own. Recorded as a decision — self-service is cheap to
add later and nobody has asked for it.

**Name resolution is tiered: own org wins, then granted orgs.** Once boards can
be shared, two boards can answer to `nrf52840-dk-3`. A board acquired by grant
must never shadow your own hardware for `ctl release` / `ctl power-cycle`, so
candidates in the caller's own org win outright and ambiguity is reported only
for a tie *within* the winning tier.

The escape hatch is a **qualified name**, and its grammar has one subtlety worth
recording because getting it wrong made the escape hatch unreachable in the
first implementation: a node id is **already org-namespaced**
(`state.rs::node_id_for` builds `NodeId("{org}/{name}")`, so the same machine
name in two tenants is two nodes), which means a `BoardRef` has *four*
slash-separated segments, not three. Splitting a typed name into `[org, node,
name]` therefore cannot address a single real board. Instead the board name is
the **last** segment and any prefix is matched against the node's short name,
its full id, or `org/node-id` — the last being the `BoardRef`'s own `Display`,
so a key pasted out of `ctl list` works verbatim. Since org ids became ULIDs,
the coordinator also accepts the org's **name** as the qualifier
(`ariel-os/rpi-1/dk-3`), looking up names only for orgs the caller may reach
(`BoardRef::answers_to_in`). The grammar lives on
`BoardRef::answers_to` so the coordinator's resolver and `ctl release`'s lookup
cannot drift apart. All of it is resolver-side: `BoardName` stays an opaque wire
string.

**Lease bookkeeping follows the board's org**, not the holder's: a lease on org
A's hardware belongs in org A's lease table and audit log, whoever is holding
it.

**Delegation ingress is `GET /delegate`** (§3.5): the sandbox presents the
capability token as its bearer, the coordinator verifies its own signature,
and a flat message allowlist applies — open a channel on *this* lease, relay
bytes, close. No `Lease`, no `Extend`, no `Release` (the delegator owns the
lease lifecycle; the sandbox's only lease-affecting power is letting it expire),
no fleet enumeration, no grant verbs, and **no `Subject` constructed anywhere on
the path**. The handed-out token is the intersection of what was asked for and
what the delegator may actually do — you can never delegate more than you hold
— and it is re-intersected with the delegator's *current* access at every
channel open, so revoking the delegator's grant also narrows the sandbox. A
contended `ctl delegate` prints no token and exits non-zero: a handoff script
must not mistake a queue slip for a board. It also leaves **no waiter** behind —
it goes through the scheduler's non-enqueueing `try_lease`, because a waiter
left by a verb that returns immediately could later be promoted onto a board
nobody is holding.

**Two data-plane tokens, both carried explicitly.** `CoordToSidecar::
ChannelOpened` carries the exact capability-token bytes the coordinator sent the
node. Previously the sidecar exported the *lease grant's* token as
`PROBE_RS_REMOTE_TOKEN` and the two matched only by coincidence — same fields,
deterministic ed25519 — a coincidence that an `extend` already broke (it
rewrites the expiry the channel mint reads) and that attenuation breaks by
construction. The wire field removed the whole class of "two mints must be
byte-identical" bugs. Protocol 6 → 7.

Since protocol 11 the two data-plane jobs that field was doing are **split**,
because `probe-rs serve` is now reused across a holder's invocations (§4.2):

- `ChannelOpened { token }` / `OpenSession { token }` — the **capability** token,
  unchanged in every respect. Per channel, re-attenuated to the holder's current
  effective ops at every open, and verified by the node (`token::verify_wire`)
  before it acts. This is authorization, and it stays exactly where it was.
- `ChannelOpened { serve_token }` / `OpenSession { serve_token }` — the
  **`probe-rs serve` user token**: a lease-scoped hex secret the coordinator
  derives as `HMAC-SHA256(signing seed, "probefleet/serve-token/v1" ‖ lease ‖
  board)`, the node writes into the board's `.probe-rs.toml`, and the sidecar
  exports verbatim as `PROBE_RS_REMOTE_TOKEN`. It authenticates the agent's own
  loopback splice, not the remote user; per-channel attenuation stays at the
  coordinator, where it is actually enforced.

The serve token is scoped to the lease rather than the channel because a reused
server reads its Figment config exactly **once, at startup**: a per-channel value
would force a respawn per invocation, which is the `errno 16` bug §4.2
describes. Derived rather than stored, so there is no per-lease map to expire in
`tear_down_lease`, `sweep_once` and the revocation cascade. Lease ids restart at
1 on a coordinator reboot, so a post-restart lease can re-derive a pre-restart
token; exposure is nil, since the port is loopback-only, every path to it is
authorized per channel, and the process the old token addressed was killed at
release. Neither token ever reaches the browser (§4.2 of `web-ui.md`, D4).

**A channel dies with its invocation; a lease does not.** The rule is enforced
in three layers, because each covers what the others cannot:

1. the invocation closes its own channel when the child returns, and waits for
   the coordinator's `ChannelClosed` (the shim exits immediately after, so an
   unacknowledged write races process teardown). This happens whatever the lease
   disposition — a cached lease is kept, its channel is not;
2. a **dropped connection**'s channels are closed by the coordinator
   (`drop_sidecar`, and the `/delegate` route's twin), which covers a sidecar
   that is killed rather than returning. Keyed on the connection's handle, not
   the lease: two connections may legitimately hold channels on one lease;
3. `PROBE_RS_ATTACH_TIMEOUT` defaults so the node's shared `ProbeBroker`
   *sequences* whatever overlap remains instead of refusing it (§4.2).

Without (1) nothing on the lease-cache-hit path ever closed a channel at all —
`Disposition::Keep` sends no `Release`, and the node reports `SessionClosed` only
in reply to a `KillSession` — so a reused server kept the previous invocation's
`ProbeLease` and the next `attach` was refused.

### 6.6 Lease lifecycle

- `request{constraints, duration, priority}` → one of **four** outcomes, not two:
  - `Leased{board, node, channel, token, expires}`;
  - `Queued{position}` — matching boards exist in the caller's reach but all are
    busy. **The only outcome that enqueues.** A sidecar waits for the promotion
    push; `ctl lease` prints the position and exits 0;
  - `NoCandidate{selector, reachable}` — nothing the caller may reach matches
    the selector, in *any* state. Waiting cannot help, so nothing is queued;
  - `AtCap{held, cap}` — the caller is at `max_concurrent_per_subject`, so the
    selector was never evaluated. Also not queued.

  The split exists because one `Queued` for all of these blamed the fleet for a
  selector typo and for the caller's own budget alike, and `position: 0` was not
  a usable tell (it counts only waiters with an identical selector). Deciding
  the cap *before* candidacy is what keeps the `AtCap` message honest.
  Protocol 8 → 9.
- Heartbeat renews; missed heartbeats free the board and trigger node cleanup.
- **Promotion is pushed.** When a board frees up, the promoted waiter is sent
  its grant on the connection that queued for it (`RequesterId`, minted per
  connection). If that connection has gone, the promotion is *undeliverable*:
  the lease is closed again and the board handed to the next waiter, rather than
  left marked `Leased` to somebody who has exited.
- **A disconnect drops queued requests, not held leases.** Closing a connection
  removes that connection's waiters — nobody is left to receive a promotion —
  while a lease it holds survives to its TTL, because a lease outlives one
  connection (a sidecar reconnects; `ctl` dials once per command). This is
  deliberately *not* the same question as the revocation cascade's
  refresh-not-drop rule in §6.5: there the subject is present and blameless and
  only its reach changed; here the caller is gone.
- **Fairness v1:** FIFO queue + per-subject concurrency cap + priority classes
  (interactive dev > nightly CI > soak).
- Leases are **org-scoped** (by the board's org), and the per-subject
  concurrency cap is keyed by the rendered `SubjectKey`.
- Lease records are the natural basis for future metering (lease-seconds per
  org); no billing is built now, but the data is recoverable by construction.

### 6.7 CI: workload identity

§6.4's bootstrap table has a "CI worker" row and a three-sentence trust rule.
This section is what that row turned into.

A CI job authenticates with a **workload token**, exchanged per job at
`POST /auth/token` from a credential the job already has and the fleet never
stored. The GitHub Actions path is the real one: a job with
`permissions: id-token: write` mints a signed OIDC JWT from
`https://token.actions.githubusercontent.com`, the coordinator verifies it
against the issuer's JWKS, and **no secret ever enters the runner**. The
auth-key path below is the fallback, and it is honestly worse.

#### The subject is a repo, in a namespace that is not an org

A workload's subject key is `gha/workload:<owner>/<repo>`.

`gha` occupies the slot a `SubjectKey` would otherwise fill with an org id, and
it is a reserved **namespace**, not a tenant. That is not a shortcut: the fact a
workload token proves — "a job in repo `owner/name`" — is genuinely
org-independent. Several orgs may each grant the same repo access to their
hardware, and the repo is a member of none of them. Stamping one org onto the
identity would either pick an arbitrary winner among the granting orgs or invent
a membership that does not exist. So the token row records the credential and
the claims, and every authorization decision goes through `grant` — the one
lookup in the tree that is deliberately subject-scoped rather than org-scoped.

`gha` is **not** an org row: it is a reserved name in fleet's forgs schema
(§6.1), so no user or org can ever be called that, at any creation path
(signup, rename, `org create`, `default_org`). A workload acts in no org
(`Subject::org()` is `None`); where a lease path wants an org for its audit row
(`extend_lease`, `tear_down_lease`) it uses the **board's** org, falling back
to the acting org only when there is one, and otherwise skips the row rather
than inventing a namespace — so no org-scoped
row is ever keyed on `gha`.

A subject id containing a slash round-trips because `SubjectKey::parse` splits
at the first `/` only if it precedes the first `:`, so
`gha/workload:ariel-os/ariel-os` round-trips exactly.

#### `repository_owner` is verified, recorded, and never consulted

This is the security-relevant decision of the whole path.

`repository_owner` is required as a claim and refused if absent, written to the
token row and into the audit detail — and it takes no part in any authorization
decision. Access needs an explicit **per-repo** grant
(`grant --repo owner/name`). A fork, or a newly created repo under a granted
owner, produces a different subject key, matches no grant, and is refused
(`401 invalid_grant`, audited as `workload.reject.no_grant` with repo and
owner). There is deliberately no `--repo-owner` flag to type.

Repo strings are lowercased on both sides — grant creation and claim ingestion —
by one shared function (`forgs::subject::normalise_repo`). GitHub repo names
are case-preserving but case-insensitive, and a case difference between the two
spellings would become a silent denial that looks like a coordinator bug.

#### What is verified

All of it explicitly, none of it inherited from a library default:

- **Algorithm**: an allowlist of exactly `[RS256]`. This is what makes the
  `alg: none` / HS256-key-confusion family (a token signed with the *public* key
  as an HMAC secret) unrepresentable rather than merely unlikely.
- **`kid`**: mandatory. Without one there is no way to say which key was meant,
  and "try every key in the set" turns a rotation window into a second chance.
- **Issuer and audience**: exact match against configured values.
- **Expiry and not-before**: against the coordinator's injected clock *only*.
  The JWT library's own `validate_exp` / `validate_nbf` are turned **off** (with
  `exp` kept in `required_spec_claims`, so a token without one is still refused),
  because a second invisible clock inside the library would disagree with the
  coordinator's `Clock` seam and produce a test that passes for the wrong reason.

An **unknown `kid` triggers exactly one JWKS refresh** — that is what a key
rotation looks like, and waiting out the refresh interval would break every CI
job in between. That refresh is rate-limited by `jwks_min_refetch_secs`
(default 60s), because the `kid` is attacker-chosen: without the floor, a stream
of invented `kid`s turns `POST /auth/token` into a fetch amplifier aimed at the
issuer. A failed fetch never flushes a good cached set — GitHub's signing keys
outlive the refresh interval by a wide margin, so serving the cached set through
an issuer outage is the safer failure.

#### Audience has no default, deliberately

`audience` is required, and `validate()` refuses a `[github_actions]` table
without one. GitHub's *default* `aud` is `https://github.com/<owner>`, which is
not specific to any service: a token minted for some other system under the same
owner, which also took the default, would then be replayable against this fleet.
Set it to the coordinator's `public_url` and have the workflow request that
audience explicitly (`ci login --audience`).

#### Failure shapes

| condition | answer |
|---|---|
| no `[github_actions]` table | `503 workload_unconfigured` |
| any verification failure | a flat `401 invalid_grant` |
| verified token, no live grant | `401 invalid_grant` too (audited as `workload.reject.no_grant`) |

Every verification failure — expiry, audience, issuer, signature, missing claim,
unknown `kid` — answers the same flat `401`, with the reason in the audit log
and never in the body. No oracle.

A grantless repo is deliberately not distinguishable from the outside either:
it gets the same flat `401`, and the coordinator records
`workload.reject.no_grant` with the repo and the owner beside it, so the "but I
granted the org!" case is one audit line to diagnose — but the operator has to
read the coordinator's audit/log to tell it from a signing problem.

#### Token TTL, and the bound with no refresh path

`workload_token_ttl_secs` defaults to 3600 and is capped at 12h;
`Policy::max_duration_ci` is also 3600. There is **no refresh path for a
workload token** — `Refresh` is session-only — so a job that runs longer than the
token's TTL must re-run `ci login`. That is an acceptable v1 bound, but it is
stated here and in `docs/ci-github-actions.md` rather than left to be discovered
as a flake. (A persistent sandbox escapes the bound by re-**redeeming** a stored
key rather than refreshing a token — see "A persistent, self-renewing sandbox
session" below, which does not contradict this.)

#### A workload's lease is clamped to CI priority

Whatever priority the request carries, a `SubjectKind::Workload` lease request
is clamped to `Priority::Ci`. §6.6's fairness ordering is "interactive dev >
nightly CI > soak" and priority is a plain wire field, so without the clamp a CI
job outbids a human at a desk by setting it. This is not an edge case: the
sidecar sends `Priority::Interactive` unconditionally, so the clamp fires on
*every* CI lease. `Policy::max_duration_ci` then applies to it, and extension
inherits the clamp for free — `Scheduler::extend_lease` re-derives the renewal
from the **recorded** priority *and* the **recorded granted duration**, both of
which already carry the clamp (the duration was capped under the clamped
priority at grant time), so there is deliberately no second guard in
`extend_lease`.

The clamp orders contention; it does not make contention painless. A workload
whose request finds every matching board busy is `Queued` like anybody else, and
the sidecar now **waits** for its turn rather than failing: it parks on the
control connection for the coordinator's promotion push, bounded by
`PROBEFLEET_QUEUE_WAIT` (client-side, default 300s; `0` restores the old
fail-fast behaviour). Only a wait that expires is an error. That is what lets a
matrix wider than the fleet run to completion instead of failing legs, so
`max-parallel` is now a throughput knob rather than a correctness requirement.
Since every job in a repo is the *same* subject, `max_concurrent_per_subject`
is still effectively a per-repo cap and a wide CI matrix still hits it — but it
now says so (`AtCap`) instead of reporting contention.
`docs/ci-github-actions.md` says all of this in the operator's vocabulary.

#### The verb surface behind `/client`, walked

The route allowlist admits `Session` **and** `Workload` on `/client`;
`/agent` admits node tokens only and `/auth/keys` sessions only, so a CI job
cannot enroll a node or mint credentials. But a route allowlist is only a fence if the verbs behind the
route have been walked, so they were:

| verb | gate | workload |
|---|---|---|
| `Lease` / `Extend` / `Release` / `OpenChannel` / `CloseChannel` | `board_access` / `require_lease_control` | allowed — this is the CI story |
| `ListBoards` / `Who` | access-scoped | allowed |
| `ListNodes` | `require_role(Member)` | denied |
| `Logs`, `GrantCreate` | `require_role(Admin)` | denied |
| `GrantList` / `GrantRevoke` | `require_role(Member)` | denied |
| **`Delegate`** | `board_access` **alone** | **explicitly refused** |

`ListNodes` (`ctl nodes`) carries the same `require_role(Member)` gate as the
grant verbs, and therefore the same workload answer, because it dispatches to
the very `list_nodes_core` the browser API's `GET /api/v1/nodes` calls: the CLI
and the web UI cannot drift on who may see a node. It exists because
`ListBoards` is board-shaped — a machine that has plugged in no probes has no
row there, and node *tags* (which every `tag=` selector matches against) were
otherwise visible only in the browser. Both `ctl list` and `ctl nodes` also take
`--json`, which emits the wire payload verbatim; that is deliberately a
different contract from the `/api/v1` bodies, which are the web UI's and are
re-shaped for it.

`Delegate` was the one verb gated by `board_access` and nothing else, so a
workload would otherwise be able to mint a capability token for a lab board and
hand it to something else. It is refused in `Coordinator::delegate` rather than
allowed by omission: nothing in the CI story needs it, v1 gives an operator no
way to see that a CI job re-delegated their hardware, and allowing it later is a
strictly smaller change than withdrawing it.

#### Metering falls out; billing is not built

`leases` rows are never deleted — `close_lease` sets `closed_at` and
`close_reason` — and `holder` is the rendered subject key. So a released CI lease
survives as a row with `holder = "gha/workload:owner/repo"` and
`granted_at`/`closed_at` set: lease-seconds per repo, recoverable by
construction. Beside it, each exchange writes a `workload.token.mint` row to
forgs' audit table, and the token row records the verified claims (repo,
owner, ref, workflow, run id). No billing is built.

#### The auth-key fallback, which is the weak path

A self-hosted Jenkins box has no workload identity to offer, and heterogeneous
runners are a stated requirement, so an API key has a `purpose`: `node` keys
enroll machines, `ci` keys (payload `{"tags":[…],"ops":[…]}`) are workload
credentials. The purposes are disjoint — forgs checks the purpose **before**
the consume, so a `node` key presented at `/auth/token` is refused without
burning a single-use key, and a `ci` key cannot enroll a node.

Redeeming a `ci` key (`POST /auth/token`, `grant_type: api_key`) does **not**
widen `board_access`. forgs consumes the key and derives the subject
`<org>/workload:key:<hash8>` (or `<org>/workload:agent:<name>` for a key minted
`--name <name>` — see below); fleet's `on_workload_redeemed` hook then upserts
an *ordinary grant* — the same kind of row `grant --repo` writes, evaluated by
the same code and revocable by the same verb — whose selector and ops come from
the key's payload; forgs then mints the workload token. The grant's id is
deterministic (`identity::ci_grant_id`: a ULID-shaped digest of
`(org, subject)`), so a multi-use key redeemed by twenty runners upserts one
row, one grant and one concurrency budget, and the revocation cascade computes
the same id from the same key. `grant list` prints it like any other grant id
and `grant revoke <prefix>` accepts it. Revoking the **key** does the same
teardown and more (forgs' `on_revoked` hook → fleet deletes the grant and runs
the §6.5 cascade), since it takes the credential with it.

Stated plainly: this is a **long-lived bearer secret sitting in somebody else's
CI configuration**, usable by anyone who reads that configuration or a leaked
log. What bounds it is org scope, the selector (a `ci` key with **no tags** is
refused at both the mint and the redemption, because an empty tag set is an
empty selector and matches every board in the org), the ops, expiry, and
revocability — and revoking the key cascades through the whole grant-revocation
path of §6.5, so live leases are torn down rather than waiting out a TTL. A `ci`
key's grant inherits the key's expiry, or gets a bounded 30-day one if the key
never expires: a shell-minted perpetual key is an operator's informed choice
about the *key*, not a choice to share the org's hardware forever.

Prefer the OIDC path wherever the runner can mint an identity.

#### Named identities: an agent that survives key rotation

For an unnamed key, both the subject (`key:<hash8>`) and hence the grant id
above are functions of the *credential*. So rotating a key — mint a new one, retire the
old — produces a **new subject and a new grant row**: the audit trail forks, the
per-subject concurrency cap resets, and the old grant lingers. A long-running
agent or CI runner has no persistent identity at all.

`auth-key create --purpose ci --name <name>` gives it one (`--as` is still
accepted as a deprecated alias). The name is stored in
`forgs_api_key.subject_name` (NULL, not `''`, means "no name"), and redemption
then builds the subject `<org>/workload:agent:<name>` and a grant id derived
from `(org, subject)`. Because the upsert is keyed on the grant id, a re-minted key with the same `--name`
re-upserts the **same row**: same audit history, same concurrency budget, same
revocation handle. Nothing downstream changes — `board_access`, `Access`, the
scheduler and the audit log are all subject-key-generic, and `SubjectKey::parse`
splits at the *first* `:`, so `agent:<name>` round-trips exactly as
`key:<hash8>` does.

The name is validated at mint time (`forgs::subject::normalise_service_name`) with the same
discipline as `normalise_repo`: trimmed, **lowercased** — so a rotation typed
months later is the same identity rather than a silent fork — restricted to
`[a-z0-9._-]` starting with a letter or digit, and capped at 64 characters. The
charset is what makes a chosen name structurally unable to spell the
`key:<hash>` form (no `:`) or to be mistaken for a `gha/workload:owner/repo`
repo subject (no `/`). It is org-scoped, since the subject carries the org, so
two tenants may each have a `builder`.

**The grant id mixes the org into a digest, and that is not decoration.** A
grant id is a *global* key. An id spelled from the name alone would let org B's
redemption address org A's row; forgs additionally refuses an upsert whose id
exists in another namespace (`GrantConflict`, surfaced as `403`), but the
digest over `(org, subject)` is what makes the collision impossible in the
first place. The cost is that the id is opaque; the row's `subject`, which
`grant list` also prints, shows `<org>/workload:agent:<name>` in clear text.

A named identity is also an ordinary grantee, so
`grant acme/workload:agent:builder --select …` works and gives it access beyond
what its redemption synthesises. Such a grant has an ordinary random id and is
*not* touched by the key-revocation cascade below, which keys on the synthesised
id — it is the one grant that survives.

**The trade, which is the whole point and a security-relevant surprise if
unstated: two live keys sharing an `--name` are one identity, and the grant
belongs to the identity, not to the key.** Revoking one of them tears down that
shared grant and every live lease held under the name — including another key's
runner, mid-job. It does not end the identity: a surviving key with the same
name re-creates the grant on its next redemption, and workload tokens already
minted stay **authenticated** for the rest of their TTL (nothing deletes
`forgs_workload_token` rows on revocation; the sweep only removes expired ones), so
the moment any surviving key redeems, that still-live token has access again
without having redeemed itself. Revoking one key of a shared identity is
therefore a **disruption, not a revocation**. To actually retire the agent:
revoke every key carrying the name, then `grant revoke` the row.

The alternative — suppressing the cascade when a sibling key shares the name —
was rejected on two grounds. Its guard cannot be made correct: "does a live
sibling key share this `subject_name`?" is a read whose answer is stale the
instant it returns, since any org member may mint a key between the check and
the delete, so it would cascade or not by race. And it inverts the failure
direction: its silent-success mode is "the operator revoked a credential and
nothing was torn down, while a runner keeps the board", where the chosen
behaviour's is "more went down than expected" — loud, immediate and recoverable,
which is the direction §6.5 already picked for every other revocation.

`--purpose agent` is accepted as a spelling of `ci` on both mint verbs, so the
vocabulary stops saying "per job" about a persistent identity. It is normalised
at the parse boundary and **stores `ci`**, so the database holds exactly two
purposes and a listing shows `ci` for such a key — because it is one. It is
CLI-only sugar: `"purpose": "agent"` on the wire is a `400`.

#### A persistent, self-renewing sandbox session (`agent login`)

A named key gives a long-running machine a persistent *identity*. It does not
give it a persistent *session*: the `prfw1_` workload token it authenticates
with lives `workload_token_ttl_secs` (default 1h) and, per the subsection above,
**there is no refresh path for a workload token**. So a sandbox had to re-run
`ci login` hourly — a cron job or retry wrapper reimplemented per sandbox, which
does not even propagate between the concurrent processes sharing the machine.

`probefleet agent login --fleet-url <url> --auth-key prfk1_… [--name <name>]`
closes that. It stores the durable key in the fleet file's `[agent]` table
(§4.1), and `ctl` and the `probe-rs` shim re-**redeem** it whenever the stored
token is within 60s of expiry.

**The mechanism is re-redemption, not refresh, and that distinction is what
keeps the earlier subsection literally true.** Nothing gained a refresh path;
`Refresh` is still session-only. Each renewal is an ordinary `api_key`
exchange — the same request `ci login --auth-key` makes, verified the same way,
upserting the same grant row — which also explains why concurrency here needs no
locking: a multi-use key is never consumed (forgs' `consume_api_key` stamps
`consumed_at` only for `single_use != 0`), so N processes renewing at once all
succeed and every token they mint stays valid. The only cost is churn, damped by
re-reading the fleet file before redeeming (§4.1).

**A single-use key is refused**, because in a sandbox with concurrent users it
breaks on the second *process*, not merely the second hour. Nothing on the wire
reveals single-use-ness — `TokenResponse` has no such field — so `agent login`
detects it by redeeming **twice**: a multi-use key yields two valid tokens (the
first is left orphaned until its TTL expires, one wasted workload-token row
per login), while a single-use key's second redemption is rejected. That
rejection, and only a rejection, produces the refusal; a transport failure on
the second call persists the first token and warns that the property could not
be confirmed, rather than telling an operator their key is spent because a
packet dropped.

**This does not weaken the per-repo OIDC path.** That path still stores nothing
and remains the recommendation for anything GitHub mints an identity for. What
changed is confined to a machine whose operator opted in by running a verb whose
documentation names the trust decision: the sandbox is single-tenant and owned
by the person storing the key. The key itself is unchanged — still org-scoped,
tag-scoped, op-scoped, expiring and revocable, with revocation still cascading
through §6.5 to tear down live leases. The one honest new exposure is that the
durable credential now sits in a `0600` file rather than only in a secret store,
which is exactly why `ci login` keeps writing no file at all: a shared runner
has no owner who can make that trade.

#### Not built in v1

**No per-ref or per-workflow conditions.** `ref`, `workflow`, `job_workflow_ref`
and `run_id` are verified as claims where present and recorded on the token row,
but nothing evaluates them: a grant to `owner/repo` is a grant to every ref and
every workflow of that repo. Capturing the claims now is what makes adding the
conditions later a pure code change. Recorded as a follow-up.


### Time-based *sharing* (decided requirement)

The lease is **not** tied to a single `probe-rs run`. A workstation can **claim
a specific board and hold it across many probe-rs invocations** — flash, attach,
reset, gdb, re-flash — to support multi-step debugging sessions. Mechanics:

- An explicit claim (`fleet ctl lease id=<board> [--duration]`, or first use under
  a selector) holds the board for the principal with an **extendable timeout**.
- Each subsequent vanilla `probe-rs …` from that workstation **reuses the
  existing lease** instead of re-queuing (sidecar caches `{board, lease, token}`
  keyed by selector + principal).
- Heartbeats / activity **extend** the timeout; an idle lease expires after its
  TTL and the board returns to the pool (agent runs cleanup: power-cycle,
  optional erase).
- Explicit `fleet ctl release` frees it immediately.

**Status.** Both halves are implemented.

The *within-invocation* half: the sidecar requests `duration_secs: 0` — i.e.
the operator's `Policy::default_ttl_secs`, never a TTL of its own — and
heartbeats it (`Extend`) for the life of one probe-rs invocation, so `attach` /
`gdb` sessions longer than the policy TTL are not swept. A renewal re-applies
the lease's *granted* duration, so heartbeating extends the hold without
promoting it to the priority-class cap. A **SIGKILLed** sidecar releases
nothing, but the board returns to the pool after one policy TTL instead of the
hardcoded hour the sidecar used to request.

The *cross-invocation* half: `probefleet_sidecar::lease_store` persists a grant under
`$XDG_RUNTIME_DIR/probefleet/leases.json` (0600, in a 0700 directory,
written via a temp file + `fsync` + `rename` under a `flock`), and
`acquire_lease` consults it before leasing. `lease_cache` stays pure logic and is
unchanged: the store feeds a loaded record through it, so the expiry /
refresh-margin judgement has exactly one implementation. `$XDG_RUNTIME_DIR` is a
unix concept, so the store is `cfg(unix)`; elsewhere it is a stub that disables
caching. The decisions worth knowing:

- **The key is `(coordinator, token fingerprint, selector fingerprint)`** — not
  the subject key. The sidecar never sees a `Subject` before it leases (the
  coordinator resolves it from the bearer token), so a pre-lease lookup cannot
  use one; the *in-memory* cache still keys on the real `SubjectKey`, recovered
  from the stored record. The token's fingerprint is `SHA-256(token)[..16]`, so
  a re-login is a miss rather than a risk of crossing identities. Nothing secret
  is written: neither the bearer token nor the grant's capability token.
- **A cache hit still opens a channel and takes a fresh per-channel
  credential.** Only the *lease* is reused. The stored grant's token is the
  delegation artefact (§6.5) and is not persisted at all.
- **Release is TTL-driven.** A shareable lease is deliberately **not** released
  at the end of an invocation — releasing it every time is exactly what would
  make the cache never hit. **This includes SIGINT / SIGTERM: Ctrl-C now keeps a
  shareable lease**, because a Ctrl-C'd `probe-rs run` is nearly always followed
  by another one. `fleet ctl release` frees the board immediately; otherwise it
  returns after one policy TTL, the same worst case as a SIGKILLed sidecar. A
  CI (`Workload`) or node holder, the delegated path, and the
  `PROBEFLEET_NO_LEASE_CACHE` opt-out all release at exit exactly as before,
  so a finished CI job never strands a board.
- **A stale hit degrades, never errors.** A hit is revalidated with a short
  `Extend` probe first. A refusal drops the entry and leases afresh; an
  inconclusive answer releases the lease best-effort before re-leasing, so a
  fresh `Lease` under an `Id` selector cannot queue behind our own hold.
- **A per-record `flock` use-lock preserves the concurrency interlock.** Without
  it two concurrent invocations would both take the cached lease and drive one
  board — the coordinator caps neither channels per lease nor sessions per
  board, and its `Queued` reply was what prevented this. A hit is only taken if
  the record's use-lock is free; otherwise the invocation falls through to a
  fresh `Lease` and takes the ordinary contention path — which since the queue
  split means it *waits* for a turn (bounded by `PROBEFLEET_QUEUE_WAIT`)
  rather than erroring immediately. The kernel releases
  the lock when the holder dies, SIGKILL included, so no staleness heuristic is
  needed.
- **A reused lease id is cross-checked against the board.** Lease ids restart at
  1 on every coordinator boot and nothing on the wire identifies a boot, so a
  persisted id can name a different lease after a restart. The channel token
  carries the `BoardRef` it was minted for; a mismatch closes the channel and
  re-leases cold. Adding a coordinator boot id to `Welcome` would be the
  systemic fix and is a follow-up.

This reduces re-lease queue collisions but does not remove them: two invocations
starting from a *cold* store still both send `Lease`, and under an `id=`
selector the loser is queued. That is the scheduler-queue work, and independent
of this.

This is what makes remote DX feel local: you grab a board, iterate freely, then
let it go — exactly like a board on your own desk.

## 7. probe-rs CLI compat surface (ground truth from laze)

From `ariel-os/laze-project.yml`, the `probe-rs` module emits exactly these:

| laze task | command | session shape |
|---|---|---|
| run (`CARGO_RUNNER`) | `probe-rs run ${PROBE_RS_PROTOCOL} --chip ${PROBE_RS_CHIP} --preverify <elf>` | flash + RTT + **embedded-test runner**; streamed stdout; **exit code is the test result** |
| flash-erase-all | `probe-rs erase --chip … --allow-erase-all` | one-shot |
| flash | `probe-rs download --chip … <elf>` **then** `probe-rs reset --chip …` | two one-shots |
| attach | `probe-rs attach --chip … <elf>` | long-lived RTT stream |
| debug | `probe-rs gdb --chip …` | long-lived gdb TCP server |
| reset | `probe-rs reset --chip … ` | one-shot |

Observations that shape the sidecar:

- **`--chip` is the only board selector laze passes.** There is no probe-serial
  in the recipe. The sidecar gets the *board* from a fleet selector (env/token)
  and leases it; **probe + chip are then selected in-band** by the genuine
  probe-rs client against the agent's per-board `serve` (no CLI injection — see
  §4.2). `--chip` flows through untouched as part of the client's `AttachRequest`.
- **The sidecar runs the genuine `probe-rs` client** (argv0 shim that sets
  `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN` to a local fleet endpoint).
  Because the real client computes the **exit code** locally as a byproduct,
  exit-code propagation is **free** — the relay only tunnels RPC frames. (Do
  *not* reimplement the client, or we'd have to re-derive exit-code logic.)
- **`gdb` is special (not remote-capable in probe-rs 0.31 or 0.32).** It is *not*
  expressed over postcard-rpc; the agent runs `probe-rs gdb` locally and the
  fleet tunnels its raw gdbremote TCP as a **second opaque channel**
  (`ChannelKind::Gdb`). The **sidecar** opens a local TCP listener (default
  `127.0.0.1:1337`, honoring `--gdb-connection-string`) that the user's gdb
  client connects to (`target remote :1337`) and byte-splices it onto the gdb
  channel; the agent splices the other end to its board-local `probe-rs gdb`
  stub. The sidecar does **not** exec the genuine `probe-rs gdb` and the
  `--gdb-connection-string` flag is consumed locally (not forwarded to the
  agent, which picks its own ephemeral port).

Proposed selector convention (additive, no laze change required):

- `PROBEFLEET_BOARD` — board **model**: any idle board of that type
  (e.g. `nrf52840dk`), or
- `PROBEFLEET_ID` — one specific board, by node-local id
  (e.g. `nrf52840-dk-3`), or
- `PROBEFLEET_SELECT` — constraint expr (e.g. `tag=nrf52 && bluetooth`).
- `PROBEFLEET_TOKEN` / `…_COORDINATOR` — auth + endpoint.
- `PROBEFLEET_QUEUE_WAIT` — how many seconds to wait for a queued lease to
  be promoted before giving up (default 300; `0` = do not wait). A client-side
  patience bound, not a coordinator policy knob: how long *this* invocation is
  willing to sit in the queue is the caller's business (§6.6).
- Absent ⇒ sidecar falls back to local probe-rs (transparent local DX).
- Setting more than one of the three selector vars is `AmbiguousSelector`, not
  a precedence rule.

For interactive use the explicit subcommand also takes the selector as a flag:

```sh
probefleet sidecar --select 'tag=nrf52840dk' -- list
probefleet sidecar --board nrf52840dk -- run --chip nRF52840_xxAA app.elf
probefleet sidecar --id nrf52840-dk-1 -- run --chip nRF52840_xxAA app.elf
```

- **Flag > env**, and a flag *replaces all three* selector vars (so `--select`
  next to a stale `PROBEFLEET_BOARD` is the flag, not an ambiguity error).
  It is
  layered over the environment as an `EnvSource` overlay, not written into it.
- `--board`, `--id` and `--select` are mutually exclusive in clap; a capability
  token plus any of them is
  still refused (the board is inside the token, §6.5).
- Flags go **before** the probe-rs subcommand / `--`; everything after is
  forwarded verbatim.
- **The argv0 `probe-rs` shim has no flags** — it forwards every argument
  verbatim so laze sees a vanilla probe-rs — so laze/CI stay env-only.

## 8. boards.toml (agent-local, decided)

Declarative per-agent file mapping probe serials to board metadata.

```toml
[[board]]
id      = "nrf52840-dk-3"
serial  = "001050257890"          # physical probe serial → per-board `serve` ProbeAccess::Allow
chip    = "nRF52840_xxAA"         # informational; --chip still comes from caller
tags    = ["nrf52", "bluetooth"]
exclusive = true

[board.power]
kind = "uhubctl"                  # | "gpio" | "none"
hub  = "1-1"
port = 2

# Optional: serial ports beyond (or instead of) the auto-discovered ones that
# share the probe's USB device (§4.2 "Serial passthrough").
# uart_discover = false            # default true
[[board.uart]]
name = "console"                  # optional, default "uart<i>"
path = "/dev/serial/by-id/usb-FTDI_FT232R_A1B2C3-if00-port0"
baud = 115200                     # optional default baud
```

The node reconciles discovered probes against this file. **Whether an
undeclared probe is leasable is per-node policy** (§4.2): `adopt = "auto"`
(default for nodes created by `share`) adopts discovered probes into the owning
org with inferred tags; `adopt = "declared"` (default for auth-key / lab nodes)
reports them but keeps them unleasable until declared here. Under `auto`, this
file is annotation and override — stable ids, power wiring, curated tags —
rather than admission control. `id` is unique **within its node**, not globally
(§6.1); auto-adoption is exactly the case where a global id space breaks, since
two laptops can each plug in an nRF52840-DK.

**UI tag overrides.** An owner of the node or an org admin can replace a
board's tags from the web UI (`docs/web-ui.md` §3, "Board tags"). The override
is stored by the coordinator (`board_tag_override`), never written back to this
file: it **replaces** the tags reported from here for as long as it exists, is
re-applied on every inventory report, and is what `tag=` selectors and
`tag=`-scoped grants see — so retagging can widen or narrow which grants cover
a board, within the org's own authority. Resetting it reverts to this file's
tags. The `board` table keeps the reported tags for provenance.

A declaration always beats an adoption for the same probe, and the agent
enforces that in one place (its board lookup consults `boards.toml` first), so
it is a structural property rather than a convention every call site has to
remember. The same precedence is applied by **name** at synthesis time: a probe
whose derived id collides with a declared `id` bound to a different serial is
not adopted at all. Reporting two boards under one name would have the
coordinator keep whichever it upserted last while the agent resolved the
declared one — so a lease taken out for the adopted probe would drive the
declared board's hardware.

**Declaring a board without hand-editing.** `probefleet node board add`
discovers attached probes (the same `probe-rs list` shell-out the agent uses),
prompts for the values discovery cannot supply, and appends a `[[board]]` table;
`node board list` shows declared boards against attached-but-undeclared probes,
named by this node's `adopt` policy so the second section does not read as an
alarm on an `auto` node. Both are node-local: no coordinator, no credential.

Two properties of `add` are deliberate. It **appends only** — the previous file
contents are a byte-for-byte prefix of what it writes — because this file is a
commented reference the operator owns and the TOML serialiser in the tree is not
format-preserving; a deserialise/re-serialise round trip would silently delete
every comment. Editing and removing a declaration therefore stay hand-edits.
And it **validates the candidate text through the agent's own loader** before
writing, so a duplicate id or serial is refused with the message the agent would
have failed to start with, leaving the file untouched. Because `boards.toml` is
read once at agent startup (there is no watcher), every successful add prints
that the agent must be restarted.

## 9. Crate layout (proposed)

```
probefleet/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ probefleet-proto/             # shared wire types + ids / SubjectKey mirror, auth_api (no I/O)
│  ├─ probefleet-core/              # Board/Lease/Policy domain + scheduler (pure, unit-testable)
│  ├─ probefleet-tls/               # client trust config (WebPKI + optional pin); no client certs
│  ├─ probefleet-wire/              # WS codec + tokio-tungstenite dial-out client
│  ├─ probefleet-agent/            # probe-rs process control, USB power, boards.toml
│  ├─ probefleet-coordinator/      # sqlite state, scheduler, authz, relay, HTTP/WS surface
│  ├─ probefleet-sidecar/          # probe-rs CLI shim + relay client
│  └─ probefleet/              # single multi-role binary; thin dispatch
└─ docs/
```

`probefleet-core` stays pure so the scheduler is testable without sockets or USB.
There is no `fleet-auth` any more: identity lives in the **forgs**
workspace (github.com/kaspar030/forgs, a crates.io dependency;
`forgs` pure core, `forgs-store`, `forgs-http`, `forgs-idp`,
`forgs-client`). `probefleet-coordinator` links the server half; `probefleet` links
`forgs` + `forgs-client`; `probefleet-agent`, `probefleet-sidecar`, `probefleet-proto`,
`probefleet-core` and `probefleet-wire` link **no** forgs crate (see
`docs/cross-compiling.md`).

## 10. Open questions / decisions to confirm

**Resolved:**

- *probe-rs transport* = postcard-rpc 0.12 (confirmed from source). Data plane
  tunnels opaque postcard-rpc frames (§3).
- *"time-based"* = time-based **sharing**: extendable board claims across many
  probe-rs invocations, not lease-per-run (§6.6).
- *myelin* is **dropped**: postcard for both planes (§3).
- *Deployment model* = **hosted, multi-tenant**, behind an HTTPS reverse proxy.
- *Transport* = **WebSocket over HTTPS** (§3.5).
- *Connection auth* = **bearer tokens**; no private CA, CSR issuance, client
  certs or client cert pinning (§6.2).
- *Identity* = **forgs**. Login providers (GitHub, Codeberg/Forgejo, GitLab,
  generic OIDC) prove identity with a verified email; the username is chosen
  at signup; ids are immutable ULIDs (§6.1). GitHub Actions workload OIDC for
  CI (§6.7).
- *CLI login* = forgs' own device flow, provider-agnostic (§6.4).
- *Tenancy* = every subject and object is org-scoped; a **personal org is
  created at signup** (§6.1); team orgs are self-service (§6.1).
- *Org choice* = per request (`--org` / `?org=`), default the personal org.
- *Node registration* = **self-approving on membership**; no admin approval step
  (§6.4).
- *Probe adoption* = per-node policy, `auto` for personal nodes, `declared` for
  lab nodes (§4.2, §8).
- *Capability tokens* remain the sandbox-delegation mechanism (§6.3, §6.5).

**Still open:**

1. **Self-hosted TLS story.** A self-hosted coordinator without public DNS
   cannot get a publicly trusted certificate, so `probefleet-tls` keeps an optional
   **pinned server-cert fingerprint** (`server_cert_sha256` in the fleet
   config). Whether we
   also ship a self-hosting story beyond dev use is a **product** question, not
   an architectural one; keeping the coordinator a self-hostable artifact is
   cheap now and expensive to retrofit (NDA-bound customers may be structurally
   unable to point lab hardware at a third-party control plane).
2. **Remote probe/chip selection.** *Resolved:* `probe-rs serve` exposes all
   local probes and the client selects probe + chip in-band; the fleet fences
   each per-board server with `ProbeAccess::Allow` (§4.2).
3. **gdb / TCP tunneling.** *Resolved (v1):* `probe-rs gdb` is not
   remote-capable in 0.31 or 0.32, so the agent runs `probe-rs gdb` locally and
   its raw gdbremote TCP is tunneled as a **second relay channel** (`ChannelKind::Gdb`),
   parallel to the postcard-rpc data plane (see §4.2, §7). Both planes share the
   same opaque `DataFrame` byte-pump; the coordinator relays gdb frames
   identically and a lease may hold a data channel and a gdb channel
   concurrently. **Latency:** the splice sets `TCP_NODELAY` on both loopback
   hops and flushes each chunk immediately (no Nagle batching), so gdb traffic
   is not coalesced. gdb is request/response and tolerant of LAN-scale RTT; the
   two relay hops add ~2×RTT per round-trip, which is acceptable for
   interactive use. Revisit (e.g. a lower-overhead path) only if step-debugging
   feels sluggish on a real deployment. *Optional follow-up:* an upstream
   probe-rs feature request to make `gdb` drive a remote `Session` over
   postcard-rpc would let gdb ride the existing data plane and drop this bespoke
   tunnel.
4. **probe-rs process lifecycle.** *Resolved:* one server process per board,
   reused across a holder's invocations and recycled per lease (§4.2).
5. **Sidecar install UX.** *Resolved:* the binary dispatches on argv0, so a
   `probe-rs` symlink on `PATH` is the shim (§4.3).
6. **Where the hosted control plane runs.** Still open. Browser login and CLI
   login both need the coordinator's browser-reachable `public_url` (the OAuth
   callback is `<public_url>/auth/<provider>/callback`), but that is
   configuration: nothing is hardcoded (§6.4).
7. **Data-plane latency budget.** All traffic relays through the coordinator; if
   remote debugging proves unusably slow at WAN RTT, direct workstation↔node
   brokering (with relay as fallback) stops being an optimisation and becomes
   mandatory. Measure on a real deployment before designing it.
8. **End-to-end encryption of the data plane.** With the coordinator relaying
   bytes, a server compromise exposes firmware images and debug traffic. Making
   the coordinator an *introducer* rather than a reader is far easier to design
   in than to add later, and is a genuine differentiator for customers with
   pre-release silicon. Not in v1 scope; flagged so v1 does not preclude it.
9. **Buffer sizing.** Concurrent ops per connection + flash-chunk buffer size —
   measure against real ariel-os flash images. (Deferred to implementation.)
