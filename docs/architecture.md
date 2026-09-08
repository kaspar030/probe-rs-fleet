# probe-rs-fleet — Architecture

Status: **accepted; scaffolding**. Decision log: myelin dropped — single-stack
postcard-rpc for both data and control planes (§3). **Revision 2 (this
document): the private-CA / mTLS credential model is withdrawn and replaced by
GitHub-rooted identity with bearer tokens over WSS (§3.5, §6), the fleet becomes
multi-tenant with orgs/users/nodes as first-class subjects (§6.1), and
enrollment is re-rooted on the user rather than the coordinator operator
(§6.4).** This document records the agreed shape of the system and the decisions
still open. It is deliberately concrete about how the pieces map onto the real
`probe-rs` CLI surface that
[ariel-os / laze](../../ariel-os/laze-project.yml) emits.

> **What revision 2 supersedes.** Everything about a coordinator-run client CA,
> CSR issuance, client certificates, cert-fingerprint pinning, `agent_pins`, and
> the `coordinator enroll` → `agent init` / `ctl init` token dance is **dropped**
> (`ctl init` is deleted; `login` replaces it),
> not amended. Where an older section is preserved below for its probe-rs ground
> truth (notably §4.2), only its credential wiring changes. Capability tokens
> (§6.3) are **unchanged** — they were always orthogonal to connection auth.


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
- **Single multi-role binary** (`probe-rs-fleet`), role chosen by subcommand:
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
link is a **WebSocket** (route `/worker`) over TCP (see §4.2 / corrected by
#1965, re-verified against v0.32.0 by #3322). We do **not** parse or re-implement
it — we tunnel the raw bytes of that
connection:

```
  sidecar's probe-rs client  ──WebSocket/TCP bytes──▶  [ WSS to coordinator ]
      ──relay──▶  [ WSS to node ]  ──▶  node's `probe-rs serve`
```

The coordinator forwards opaque bytes on a leased channel; it never decodes
probe-rs traffic. The sidecar exposes a local TCP endpoint (advertised to the
genuine client as `PROBE_RS_REMOTE_HOST=ws://127.0.0.1:<port>`) and byte-splices
its accepted connection onto the relay — the same bytes flow through verbatim.

### Control plane — leases, inventory, auth, power, heartbeats

Small typed request/response + a few server→client pushes.

> **DECISION (accepted):** myelin is dropped. We use **postcard for both
> planes**. Coordinator→node commands ride the node's single dial-out
> connection; the opaque data channel is multiplexed over the same pipe.
> Revisit only if control ergonomics force it.

### 3.5 WebSocket over HTTPS (revision 2, decided)

Revision 1 ran a bespoke TCP protocol — `u32`-LE length prefix + postcard body
(`fleet-wire`) — with rustls terminated by the coordinator itself on port 7000.
**That is replaced by the same postcard frames carried as WebSocket binary
messages over HTTPS.** Drivers, in order of force:

1. **Deployment behind an HTTPS reverse proxy is a requirement.** A proxy cannot
   route a bespoke TCP protocol; it would need `stream`-mode passthrough on a
   second port, forfeiting HTTP routing and splitting the listener story.
2. **Bearer auth gets a natural carrier** — `Authorization: Bearer …` on the
   WebSocket upgrade request, rather than an auth frame hand-rolled into the
   `Hello` handshake.
3. **OAuth device flow needs HTTP endpoints anyway** (§6.4); they share the port
   and the proxy.
4. **Port 443 traverses corporate firewalls and lab NAT**, which a custom port
   does not.
5. **probe-rs already speaks WebSocket** (`/worker`), so the whole stack becomes
   one protocol family.

What changes: the length prefix disappears (WebSocket already delimits
messages), and `fleet-wire`'s codec becomes a thin adapter over WS binary
payloads. What does **not** change: the `fleet-wire` envelopes, the relay, the
byte-opaque splice, and every `fleet-proto` payload type.

Routes:

| Route | Who | Purpose |
|---|---|---|
| `GET /agent` (WS upgrade) | nodes | persistent dial-out control + data |
| `GET /client` (WS upgrade) | ctl + sidecar | leases, relay channels, admin surface |
| `GET /delegate` (WS upgrade) | a sandboxed agent | **relay only**, authorised by a capability token; no principal (§6.5) |
| `POST /auth/device/*` | `login` | GitHub device-flow start/poll (§6.4) |
| `POST /auth/token` | CI, nodes | token exchange (workload OIDC, auth keys) |
| `POST /auth/keys` | org members | mint / list / revoke the org's auth keys (§6.4) |
| `POST /node/register/start` | headless nodes | begin an approval-pending registration (§4.2 rung 3) |
| `POST /node/register/poll` | headless nodes | redeem an approved registration for a node token |
| `POST /node/register/approve` | org members | inspect / approve / deny a pending registration |
| `GET /node/approve` | anyone | static page: what to run to approve one (and a link to `/ui/approve`) |
| `GET /auth/github/start` | a browser | 302 to GitHub's authorize endpoint (browser login, `docs/web-ui.md` D1) |
| `GET /auth/github/callback` | a browser holding a valid `state` | exchange the code, set the session cookies, 302 `/ui` |
| `GET /api/v1/*` | a browser session, or a bearer | the browser-facing JSON API (`docs/web-ui.md` §3) |
| `GET /` , `GET /ui` | a browser | 302 to `/ui/` |
| `GET /ui/` and each client-side route, with or without a trailing slash | a browser | the web UI's shell, embedded in the binary (`docs/web-ui.md` D3) |
| `GET /ui/a/{hash}/*` | a browser | one embedded asset, immutably cacheable |
| `GET /healthz` | proxy | liveness |

`/auth/github/*`, `/api/v1/*` and `/ui*` are the **browser surface**, added by
`docs/web-ui.md` and designed there rather than here — named by prefix rather
than by position, so the next row anyone adds to this table does not silently
leave this sentence pointing at the wrong rows. Three properties of it belong
here rather than only in that document:

* `/api/v1/*` is the **only** prefix on which a session cookie is an accepted
  credential. Every other route in this table requires an explicit
  `Authorization: Bearer`, including `/agent`, `/client` and `/delegate` (a
  browser must never drive a control-plane WebSocket by ambient authority) and
  the CLI's `/auth/token` and `/auth/keys`.
* Mutating `/api/v1` calls whose credential arrived in a cookie must also carry
  an `X-Fleet-Csrf` header, and the coordinator emits **no CORS headers
  anywhere**, which is what makes that header a second independent control.
  Phase 1a shipped exactly one mutating route (`POST /api/v1/session/logout`),
  so the machinery was exercised before there was anything worth abusing
  through it; phase 1b added the node verbs (`PATCH` / `DELETE
  /api/v1/nodes/{name}`, `POST /api/v1/nodes/pending/{code}`) and phase 1c the
  outward-pointing ones (grants, auth keys, power-cycle, lease release) behind
  the same single check.
* **The `/ui*` routes authenticate nothing and there is no global router
  fallback.** The shell has to load before a session exists, since login is a
  page inside it, so the asset routes are unauthenticated and set no cookies;
  they serve only bytes compiled into the binary. Every catch-all is scoped
  under `/ui/`, which is what makes "the UI cannot swallow another prefix" a
  property of the router's shape rather than of a test — an unknown top-level
  path is an empty 404. Please do not add `.fallback(...)` to fix a
  client-side route that 404s; add the page to `PAGES` in
  `crates/fleet-coordinator/src/assets.rs`, which registers both its bare and
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
terminate TLS itself. Either way the framing above is unchanged. `fleet-tls`
shrinks to client-side trust configuration: normal WebPKI roots by default,
plus an optional pinned server-cert fingerprint for local/self-hosted
deployments with no public DNS (§10). Everything to do with **client**
certificates — CA loading, CSR signing, `PinnedServerCertVerifier` as a
bootstrap mechanism, `principal_from_cert`, `node_id_from_cert` — is deleted.

## 4. Roles

### 4.1 `coordinator`
Central daemon, single node, sqlite (via `sqlx`) for state. Responsibilities:

- **Inventory:** reconcile board reports from all agents into one fleet view.
- **Scheduling & leases:** match constraint requests to idle boards; queue when
  none free; lease TTL + heartbeat renewal; fairness/quotas.
- **Auth:** authenticate bearer tokens → a [`Subject`](#61-identity-model-revision-2);
  evaluate grants; issue per-lease capability tokens.
- **Relay (data plane):** splice a sidecar's probe-rs session to the owning
  agent. The coordinator does **not** parse probe-rs traffic; it forwards
  opaque framed payloads on a leased channel. Restartable without dropping
  active TLS sessions within lease TTL is a goal, not a v1 guarantee.
- **Audit log:** who leased what, when, power events, faults.

Does **not** touch USB.

#### Config & scaffolding (`coordinator init`)

The coordinator reads a TOML config, discovered at the XDG path
`~/.config/probe-rs-fleet/coordinator/coordinator.toml`; `--config` /
`PROBE_RS_FLEET_CONFIG` override it. Generated key material and the SQLite
database default to `~/.local/share/probe-rs-fleet/coordinator/`.

`probe-rs-fleet coordinator init` scaffolds a ready-to-run coordinator:

- generates a fresh ed25519 capability-token signing seed
  (`signing.seed`, 64 hex chars, `0600`);
- generates a fresh secret for signing user session tokens (`session.seed`,
  `0600`);
- writes a populated `coordinator.toml`: `listen_addr` (loopback by default,
  since an HTTPS reverse proxy fronts it), `public_url` (the externally
  reachable origin handed to clients and nodes), the GitHub OAuth app's
  `[github]` block, and the lease policy. Omitting `[github]` is a supported
  deployment (air-gapped, or development): the device-flow routes then answer a
  named `503` and `coordinator user-token` remains the bootstrap path.

It no longer generates a client CA, a server cert, or a server key: TLS is the
reverse proxy's job (§3.5). `init` refuses to overwrite existing files unless
`--force` is passed.

**`coordinator enroll` is demoted.** It survives only as the **auth-key minter**
for unattended nodes (§6.4) and as an admin escape hatch; it is no longer on the
normal path for either users or CI. Its old CSR-issuing behaviour is gone.

Since `POST /auth/keys` landed, minting an auth key **no longer requires a shell
on the coordinator host at all**: any org member mints one with
`probe-rs-fleet auth-key create`, authenticated by their `[user]` session. The
`coordinator auth-key` / `auth-keys` / `auth-key-revoke` verbs remain for the
self-hosted operator, for the air-gapped case, and for the one thing the API
refuses — a key that never expires. `coordinator auth-key` takes the same
`--purpose` / `--ops` as the API path, so a never-expiring **CI** key
(`--purpose ci --ttl 0`) is mintable here and only here; the grant its
redemption synthesises is still capped at 30 days and renewed on each
redemption, so a perpetual key is a rolling share, not a perpetual one.

#### Per-fleet config layout (revision 2)

Revision 1 organised client config **per role, then per profile**
(`<config>/agent/<profile>/`, `<config>/client/<profile>/`). That is the direct
cause of the laptop dual-role conflict (§6.4): a machine that is both a user and
a node had to be enrolled twice, into two unrelated identities, in two trees,
each separately told the coordinator address and trust material.

**Config is now per *fleet*, not per role:**

```
~/.config/probe-rs-fleet/fleets/<name>.toml
```

```toml
# The fleet's coordinator.
url = "https://fleet.example.com"
# Optional: pinned server-cert SHA-256, for self-hosted deployments
# without a publicly trusted certificate.
# server_cert_sha256 = "…"

[user]                 # present once `login` has run
session_token = "…"    # short-TTL bearer, refreshable
org = "gh-4242"        # the org **id**, not the login (see below)
login = "kaspar"       # cached for display only
expires = 1788600000

[node]                 # present once `share` / `node up` has run
node_token = "…"       # long-lived machine bearer, auto-rotating
node_id = "gh-4242/kaspar-laptop"
coordinator_token_pubkey = "…"   # verifies per-lease capability tokens

[agent]                # present once `agent login` has run (§6.7)
auth_key = "…"         # the DURABLE credential, re-redeemed on demand
name = "desk-bot"      # the `--as` identity; display only, not verified
workload_token = "…"   # the current short-lived session
expires = 1788999999   # required here, so staleness is knowable offline
```

**`org` is `gh-<github_user_id>`, never the login.** This is load-bearing, not
cosmetic. Org creation is `ON CONFLICT DO NOTHING`, so if a personal org were
keyed by login slug then: bob renames on GitHub → alice claims the freed `bob`
login → alice logs in → the create no-ops → **alice is provisioned into bob's
org**. GitHub documents login reuse as exactly this account-takeover vector.
`user.id` and `org.id` are therefore both derived from the immutable numeric id;
`org.slug` and `user.login` are display columns, refreshed on every login and
consulted by nothing.

A laptop that both consumes and provides simply has **both tables**. A headless
Pi has only `[node]`. A CI runner has neither (it exchanges a workload token per
job). A persistent sandbox has `[agent]` (§6.7). `--fleet <name>` /
`PROBE_RS_FLEET` select among several fleets; `default`
is used otherwise. Credentials are stored `0600`; the two tokens stay **distinct**
by design (§6.4).

This replaces `agent.toml` and `client.toml` entirely — both files are deleted.
`AgentConfig` is no longer a file format at all: the `node run` role assembles it
from the fleet file's `[node]` table plus node-local settings.

Node-local, non-credential settings move to `~/.config/probe-rs-fleet/node/`
(`node.toml` for boards path / heartbeat / erase-on-release, `boards.toml` for
the inventory). They describe the *machine*, not the fleet, so they are not
per-fleet and are not duplicated when a machine joins a second one.

Credential env vars collapse to a single `PROBE_RS_FLEET_TOKEN`; the selector
vars (`PROBE_RS_FLEET_BOARD` — a board **model** — `PROBE_RS_FLEET_ID` and
`_SELECT`) keep their names (`sidecar --board` / `--id` / `--select` override
them, §7). `PROBE_RS_FLEET_PROFILE`
is gone, replaced by `PROBE_RS_FLEET` (a fleet name).

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
**multi-use** auth key is not a rotation. `consume_auth_key` stamps
`consumed_at` only when `single_use != 0`, so each redemption mints an
independent `workload_token` row and upserts the *same* grant row — nothing is
invalidated, N concurrent redemptions all succeed, and every resulting token
stays valid. There is no correctness race to lose, only churn.

The churn is damped by **re-reading the file immediately before redeeming**, not
only on failure: a process that finds a peer's fresher token on disk uses it and
redeems nothing. Jitter and lock files are deliberately not added — they would
buy correctness that is not at stake. Correspondingly there is no
`previous_workload_token` mirroring `[node]`'s: that field exists because
rotation can lose an ack, and nothing here is ever invalidated.

There is **no migration path** from the revision-1 trees. The database is wiped
for revision 2; the documented upgrade is to delete
`~/.config/probe-rs-fleet/{agent,client}/`.

#### End-to-end deployment flow (revision 2)

```sh
# 1. On the coordinator host: scaffold signing keys + config.
probe-rs-fleet coordinator init --public-url https://fleet.example.com
#    Register a GitHub OAuth app with **Device Flow enabled**, put its
#    client_id in coordinator.toml's [github] block, then start the
#    coordinator behind your HTTPS reverse proxy. (No callback URL is
#    needed — see §6.4.)
probe-rs-fleet coordinator

# 2. On your laptop: log in. Opens a browser (or prints a code when headless).
probe-rs-fleet login --fleet-url https://fleet.example.com
#    → personal org created on first login; session cached in fleets/default.toml

# 3. Offer this machine's probes to the fleet. No token, no out-of-band step:
#    it reuses the session from step 2.
probe-rs-fleet share

# 4. Use the fleet.
probe-rs-fleet ctl list
probe-rs-fleet ctl lease --select 'tag=nrf52'

# 5. A headless Pi in the lab: prints a URL + code; a colleague approves it
#    from a machine where they are logged in.
#      probe-rs-fleet node up --fleet-url <url>       (on the Pi)
#      probe-rs-fleet node approve ABCD-1234           (on their laptop)
#    Nothing long-lived is copy-pasted, and the credential is bound at
#    approval time. For an unattended image, use 5b instead.
probe-rs-fleet node up --fleet-url https://fleet.example.com

# 5b. …or, for an unattended image, a pre-minted auth key. Mint it on your
#     laptop with the login from step 2 — no shell on the coordinator:
probe-rs-fleet auth-key create --tag lab --tag nrf52 --ttl 24h
probe-rs-fleet node up --auth-key prffk1_…
#     Self-hosted, or air-gapped, or for a key that never expires, the same
#     thing from a shell on the coordinator host:
probe-rs-fleet coordinator auth-key --org acme --tag lab --ttl 24h
#     Same verb, same flags as the API path, for a CI key that never expires:
probe-rs-fleet coordinator auth-key --org acme --tag lab --purpose ci --ttl 0

# 6. Give a colleague access to some of your boards.
probe-rs-fleet grant bob --select 'tag=nrf52' --ops flash,attach --until 2026-12-31

# 7. Hand a sandboxed agent one board, with no fleet identity of its own.
probe-rs-fleet ctl delegate --select 'tag=nrf52' --ops flash,attach --ttl 2h
#    → prints a lease-bound capability token; nothing else is granted.
```

> **Superseded.** The revision-1 bootstrap-token flow (`coordinator enroll`
> minting a single-use secret → `agent init` / `ctl init` redeeming it over a
> pinned bootstrap TLS connection for a CA-signed client certificate), the
> optional-client-auth listener branch, and the revision-1 deployment flow that
> went with them are **withdrawn** — see §6.2 and §6.4 for what replaces them,
> and the deployment flow above for the current commands. `enroll` survives
> only as the auth-key minter.


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

> **Updated by investigation (tasks #1710, #1965 — verified against the real
> probe-rs 0.31.0 source; re-verified line-by-line against v0.32.0 by #3322,
> which found no change to any of it):** The server is `probe-rs serve`. It
> takes **no `--probe` / `--chip`** — it exposes *all* local probes and the
> connecting client selects probe + chip **in-band**. So there is **no CLI
> injection point** for the agent; the earlier "agent injects `--probe`" model
> is dropped.
>
> **Correction (#1965):** the #1710 model of `serve` as a *Unix-socket, raw
> `u32-LE postcard`, `address="socket://…"`, server config via `--config`*
> transport was **inaccurate** for probe-rs 0.31 (and still is for 0.32). The
> genuine `probe-rs serve`:
>
> - **Binds TCP**, default `0.0.0.0:3000` (`TcpListener::bind`). *(0.32 update:
>   an `address = "socket://<path>"` Unix-socket scheme **does** now exist, so
>   the "no `socket://` scheme" wording above was true for 0.31 only. We
>   deliberately keep the loopback-TCP model. That is a **recorded decision,
>   not an unexamined default** — see *Rejected: `socket://` Unix-socket serve*
>   below, which closes issue #297.)*
> - **Speaks WebSocket** at route `/worker` (axum), with **challenge/token**
>   auth (`Probe-Rs-Challenge` header; client replies `sha512(challenge||token)`).
> - Has **no `--config` flag**. `ServerConfig` is the `server` field of the
>   top-level config loaded via **Figment** from `.probe-rs.{toml,json,yaml,yml}`
>   searched in **cwd → exe dir → home**. So config lives under a **`[server]`**
>   table (`#[serde(deny_unknown_fields)]`), with `[[server.users]]` entries
>   requiring `name`, `token`, and `access` (NOT `probe_access`).
> - The client honours `PROBE_RS_REMOTE_HOST` (a **`ws://` base URL** — the
>   client appends `/worker`) and `PROBE_RS_REMOTE_TOKEN`.

Decided agent model (per #1710, corrected by #1965):

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
  - **Reuse is what the process model is for, and since #512 it is what the
    code does** (it was previously only the intent: the node spawned a server
    per *channel*, and the second invocation against a board died in `nusb`
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
`--gdb-connection-string` (`crates/fleet-agent/src/gdb.rs`), so the agent keeps
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

#### Config & scaffolding (`node up`, revision 2)

The node's credential lives in the **per-fleet config** (§4.1); `agent.toml` is
deleted. Node-local settings live at `~/.config/probe-rs-fleet/node/`
(`node.toml`, `boards.toml`) — they describe the machine, not the fleet.

`probe-rs-fleet node up` registers this machine as a node and starts serving.
It obtains a node token by whichever of these applies, in order:

1. **An existing `[node]` credential** in the fleet config — just reconnect.
2. **An existing `[user]` session** (i.e. `login` has run here) — self-register
   silently against your org. This is what `share` does; membership is
   sufficient, no admin approval (decided).
3. **Interactive approval** — print a URL + short code; a human approves from a
   machine where they are already logged in (`probe-rs-fleet node approve
   ABCD-1234`). This is the headless-Pi path, and it replaces the copy-paste of
   a bootstrap token.
4. **An auth key** (`--auth-key`) — org-scoped, expiring, optionally
   single-use, carrying default tags. This is the unattended/image path.

> **Implementation status (task 3451).** All four rungs ship. Rung 3's approval
> was a **CLI verb, not a browser form**, and that was a decision rather than an
> unfinished edge: `login` is the GitHub *device* flow, which by design has no
> `redirect_uri` and no cookie session (§6.4), so a page served by the
> coordinator could not know who was looking at it. Building one would have
> meant an OAuth redirect flow plus cookies in the coordinator, which
> contradicted §6.4 and reopened §10 Q6. `GET /node/approve` was therefore an
> *informational* page that says what to run.
>
> The design deliberately did not foreclose a real browser flow later.
> Approval is keyed by `user_code` and is a pure function of `(code, decision,
> authenticated user)`, factored so that a future cookie-authenticated handler
> resolves its subject its own way and calls the same function; the node-side
> wire contract (`start` / `poll`) never learns which mechanism approved it, so
> adding one is additive and deployed agents keep working; and the page that
> would grow the form already exists at the URL agents already print.
>
> **That later arrived (task 3573, `docs/web-ui.md` phase 1b), and the
> commitment held exactly as written.** The coordinator now has an OAuth
> redirect flow and a cookie session — `docs/web-ui.md` D1 reverses §6.4's
> "no browser session" premise and records what it costs — and
> `POST /api/v1/nodes/pending/{code}` approves from the browser. It resolves its
> subject from the session cookie and calls **the same**
> `http::decide_pending_node`, with no schema change and no second binding site;
> it shares the CLI route's membership check and writes the same
> `node.approve.*` audit rows. Three things about it are worth pinning here,
> because each is a place the browser could have quietly made rung 3 weaker:
>
> * **`GET /node/approve` did not grow the form.** It stays informational and
>   reflects nothing — no code in the URL, no query parameter echoed — so it
>   cannot become a confused-deputy surface, and the URL every deployed agent
>   prints keeps meaning what it meant. Phase 2 added a static link from it to
>   `/ui/approve`, which is where the form lives.
> * **There is no pending-registration listing.** `pending_node.org_id` is
>   `NULL` until approval binds it, so a listing could only show every live
>   code in the deployment: a cross-tenant index that would turn §6.4's
>   "guess ~40 bits" into "read the list". Approval stays code-driven
>   (`docs/web-ui.md` §3/§4).
> * **The phishing warning travels with the response.** Because nothing lists
>   pending rows, the approver has only what `inspect` returns; the sentence the
>   CLI prints — you cannot see this machine, approve only an enrollment you
>   started — is a server-sent field on that response, not frontend copy.
>
> The cross-tenant code-enumeration risk below is **unchanged** by the browser
> path: same handler, same entropy, same TTL, same audit row, same "the
> enrolling machine prints which org it landed in" control.
>
> **The rung is gated on there being a human.** `--interactive` /
> `--no-interactive`, defaulting to whether stdout is a terminal: a service unit
> with no tty fails fast with remediation instead of printing a code into its
> journal and blocking for fifteen minutes on nobody. It is also tried **last**
> among the bootstrapping rungs, for the same reason in reverse — anything that
> can succeed without a human should.
>
> **User-mintable auth keys (task 3454) changed rung 3's urgency, not its
> value.** Rung 4's key no longer requires a shell on the coordinator, so
> headless enrollment was already possible for a hosted customer without rung 3.
> What rung 3 buys that a key does not: nothing long-lived is copy-pasted, and
> the credential is bound at approval time rather than minted in advance and
> carried around. That property is why it was built.
>
> One **deliberate deviation** from the order above: an explicit `--auth-key`
> beats an existing `[user]` session. Passing it is a deliberate act — a
> provisioning script run on a developer's own laptop should enroll the node it
> was told to, not the one the laptop's owner implies. An existing `[node]`
> credential still wins over everything, and is reused rather than replaced.
>
> `share` is `node up`'s rung 2 as a standalone verb, and does **not** start
> the node: it writes the credential and the node-local settings, and its
> summary points at `probe-rs-fleet node run`.

The node token is long-lived but **rotating**: the coordinator can issue a
replacement over the established connection, so a leaked token has bounded
value and revocation is a `DELETE` in the `node` table rather than a CRL.

**Probe adoption is now per-node policy, not a global gate.** Revision 1 made
every probe wait for a `boards.toml` declaration, which is right for a lab and
pure friction for a laptop:

- `adopt = "auto"` (default for nodes created by `share`): discovered probes are
  adopted into the owning org automatically, with tags inferred from the probe.
  Plug in a board, it is usable.
- `adopt = "declared"` (default for auth-key / lab nodes): unknown probes are
  reported but not leasable until declared, so CI gets stable ids and no
  surprises.

`boards.toml` therefore becomes **annotation and override** — stable ids, power
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
`boards.toml` annotates it. Two probes are never adopted: one that is `inaccessible` (the
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
boards. Before the set difference existed, board rows were only ever written and
never deleted, so every rename leaked a row — and, within one coordinator
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

#### Credentials (revision 2)

ctl and the sidecar both read the **`[user]` session** from the per-fleet config
(§4.1) — or, in CI, a token exchanged from a workload OIDC credential. The
revision-1 arrangement (a shared client certificate, discovered through two
different sets of env var names, bridged by the shim) is deleted along with the
rest of the client-cert model.

Resolution precedence is **explicit flag / env var > fleet config**. The
credential env vars collapse to a single `PROBE_RS_FLEET_TOKEN`. The *selector*
vars (`PROBE_RS_FLEET_BOARD` / `_ID` / `_SELECT`) keep their names but are no
longer the only mechanism: `sidecar --board` / `--id` / `--select` override them
(§7).

**A sandboxed agent is never given these credentials.** It receives a
lease-bound capability token instead (`ctl delegate`, §6.5).


### 4.4 Shell completion (dynamic)

The binary completes its own command line. `clap_complete`'s **dynamic** engine
(`COMPLETE=<shell> probe-rs-fleet`) installs a small shell stub that calls back
into the binary on every Tab; the binary answers with candidates computed *at
that moment*. `probe-rs-fleet completions <shell>` prints the one line that
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
data channel by the `fleet-wire` envelopes.

## 6. Identity, auth & leases (revision 2)

Revision 1 had authentication (mTLS client cert → `Principal`) and **no
authorization**: nothing consulted the authenticated principal. This section
replaces the whole credential model and adds the missing authorization layer.

### 6.1 Identity model (revision 2)

The fleet is **multi-tenant**. Every object belongs to an org; every subject acts
within one.

```
org      { id, slug, kind: personal | team }
user     { id, personal_org_id, github_user_id, login, email }
member   { org_id, user_id, role: admin | member }
node     { id, org_id, owner_user_id, name, tags[], token_hash,
           adopt_policy, last_seen }
board    { org_id, node_id, name, chip, tags[], … }   -- PK (org_id, node_id, name)
grant    { id, org_id, subject, selector, ops[], expires }
auth_key { org_id, key_hash, tags[], single_use, expires, created_by,
           purpose: node | ci, ops[], subject_name? }
```

A workload subject's id has three shapes, all of them rendered into the same
`<ns>/<kind>:<id>` key: `gha/workload:<owner>/<repo>` for the GitHub Actions
OIDC path (§6.7), `<org>/workload:key:<hash8>` for an unnamed `ci` auth key, and
`<org>/workload:agent:<name>` for one minted `--as <name>` — an identity that
survives rotating the credential. `auth_key.subject_name` is nullable, and NULL
means the hash-derived spelling, so no pre-existing key changes meaning.

Three decisions are load-bearing:

- **Everyone is always in an org; yours is an org of one.** A personal org is
  created on first login (decided). There is no user-owned/org-owned branch —
  one scoping rule everywhere, so no code path can forget the org check. Moving
  a node from personal to team use is a move, not a migration.
- **Boards are keyed `(org, node, name)`**, not by a globally unique string.
  Revision 1's flat `BoardId` breaks under both multi-tenancy and auto-adoption
  (two people plug in an `nrf52840-dk`).
- **`Principal(String)` is replaced by a `Subject`:**

  ```rust
  struct Subject { org: OrgId, kind: SubjectKind, id: String, groups: Vec<Group> }
  enum SubjectKind { User, Node, Workload }
  ```

  All three authentication paths resolve to this one shape, so authorization is
  a single mechanism regardless of how the caller proved itself.

**A note on test fixtures.** Domain identifiers in tests are built with the
production constructor, at the layer that would actually build them — a node id
via `state.rs::node_id_for`, never a hand-rolled `format!("{org}/{name}")`. A
fixture that spells an identifier itself is a second, unversioned definition of
that identifier, and it drifts: the coordinator's board fixture built bare node
ids (`node-a`) where production builds `gh-1/rpi-1` for long enough that every
qualified-name resolution test passed while addressing boards the fleet cannot
produce. The rule is *construct it the way the producing side does*, not "always
prefix": an agent genuinely does not know its own org, so the `BoardName` it
mints is correctly unprefixed, and mechanically prefixing it would manufacture a
shape production never emits. Where the constructor is out of reach — the agent
crate does not depend on the coordinator — the fixture names the shape in one
documented constant rather than repeating a literal.

### 6.2 Connection auth: bearer tokens (revision 2)

**The private CA and mTLS are withdrawn.** Deleted: `client_ca` /
`client_ca_key`, CSR generation and signing, `EnrollRequest` cert issuance,
cert-fingerprint pinning, the `agent_pins` table, the bootstrap-TLS pinning
verifier, and the optional-client-auth listener branch.

Rationale: with user identity rooted in GitHub, the CA bought nothing that
bearer tokens do not, while imposing a cert ceremony on every enrollment and
leaving **no revocation story at all** — revision 1 issued client certs that
could not be withdrawn short of rotating the CA and re-enrolling the fleet.
Under bearer tokens revocation is a row delete.

All three principal kinds present `Authorization: Bearer …` on the WebSocket
upgrade (§3.5):

| Kind | Token | Lifetime | Revocation |
|---|---|---|---|
| User | session token, minted after GitHub login | short, refreshable | delete session |
| Node | node token, minted at registration | long, auto-rotating | delete node row |
| Workload (CI) | exchanged from a GH Actions OIDC JWT, or from a `ci` auth key (§6.7) | one job: `workload_token_ttl_secs`, default 1h, capped at 12h, **no refresh path** | expiry, or revoking the per-repo grant (which tears down live leases) |

The cost, stated honestly: bearer tokens are pure bearer credentials, so a leak
is immediately usable. Short user sessions, rotating node tokens, and per-job CI
tokens bound the window.

**One extra carrier for the user token (`docs/web-ui.md` D1).** A browser
cannot hold an `Authorization` header the way `ctl` does, so a user session
token also travels in a `prfs_session` cookie — `HttpOnly`, `Secure`,
`SameSite=Lax`, `Path=/`, with `Max-Age` tracking the `session` row's own
expiry. This is a **second carrier of the same credential, not a second
credential kind**: the same `prfs1_` string, resolved byte-for-byte by the same
`fleet_auth::authenticate`, through the same single `Subject` construction site
(`http::authenticate_request_with`). The table above is unchanged — same token,
same lifetime, same "delete session" revocation.

What the carrier changes is what else the caller must prove, and where it is
accepted:

* it is accepted **only under `/api/v1/*`** (§3.5), because a cookie is ambient
  — the browser attaches it to every request to this origin, including ones
  another site caused;
* a mutating call carrying one must also carry `X-Fleet-Csrf`, a double-submit
  token `HMAC`-derived from the coordinator's existing signing seed and the
  session token's hash. Nothing is stored: no CSRF table, no second secret. A
  **bearer**-authenticated `/api/v1` call needs no such header, because that
  credential is not ambient.

The trade recorded with it: `HttpOnly` costs the CSRF machinery, and buys that a
single XSS cannot walk away with a credential that can power-cycle real
hardware. `Authorization: Bearer` from JavaScript would need no CSRF at all and
was rejected for exactly that reason (`docs/web-ui.md` §5).

### 6.3 Capability tokens (unchanged)

The coordinator mints an ed25519-signed `CapabilityToken { lease, board,
allowed_ops, expires }` per lease; the node verifies the signature **locally**
with the coordinator's public key, so there is no per-operation round trip. This
survives revision 2 untouched — it was always orthogonal to connection auth, and
it is exactly the attenuated, lease-bound, expiring credential the sandboxed-agent
story needs (§6.5).

### 6.4 Bootstrapping: one ceremony, several flavours (revision 2)

Revision 1's enrollment was **coordinator-operator-rooted**: someone with a shell
on the coordinator minted a single-use secret and sent it out of band. Every path
— user, agent, CI — went through that one manual funnel.

Revision 2 inverts it to be **user-rooted**: a human authenticates once against
GitHub, and every other credential is derived from that authority.

```
probe-rs-fleet login
  → GitHub device flow (browser, or URL + code when headless)
  → personal org created on first login
  → session token cached in the per-fleet config
```

**No callback origin is involved *for the CLI*.** The device flow (RFC 8628)
has no `redirect_uri` at all, so §10's unresolved "where does the hosted control
plane run" question does not gate `probe-rs-fleet login` and nothing in the CLI
path hardcodes a hostname. Register the OAuth app with **Device Flow enabled**;
for the CLI there is no callback URL to fill in, and this is still the whole
story for every deployed agent, sidecar and `ctl`.

**A callback origin *is* involved for the browser (`docs/web-ui.md` D1).** The
web UI cannot use the device flow as its primary login — a page that makes you
type a code into another tab is a poor front door — so the coordinator also
offers the GitHub **authorization-code** flow at `GET /auth/github/{start,
callback}`. That reverses the sentence above for one surface, and it costs
exactly one thing: a per-deployment setup step, registering
`<public_url>/auth/github/callback` in the OAuth app. Three things bound it:

* the step is **opt-in** (`github.callback_registered`). A deployment that skips
  it falls back to an in-page device-code login, which is uglier and works, so
  `[github]` stays optional and no existing deployment is broken by this;
* `redirect_uri` is derived from `public_url`, **never** from `Host` or
  `X-Forwarded-Host`. Behind the reverse proxy of §3.5 the coordinator does not
  see its own public name, and a Host-derived callback is a host-header
  injection into an attacker-chosen OAuth redirect — an account takeover. The
  callback path is fixed and the origin is configuration;
* GitHub does **not** implement PKCE (it ignores `code_challenge` /
  `code_verifier`). The parameters are sent anyway, because they are harmless
  and correct for a GHES or other-IdP future, but what actually protects the
  callback is the `state` value bound to a short-lived `HttpOnly` cookie plus
  the `client_secret` — which is therefore effectively **required** once
  browser login is enabled, unlike the device flow. Please do not record this as
  "PKCE-protected"; it is not.

The device-flow paragraphs below are unchanged and describe the CLI path, which
nothing here moves.

**The coordinator brokers; the CLI never talks to GitHub.** The OAuth app's
client id/secret stay server-side, the user's GitHub *access token* never leaves
the coordinator (it is spent on one `GET /user` and discarded), and a
self-hosted deployment can use its own OAuth app without anyone rebuilding the
CLI. Brokering is stateless — the `device_code` round-trips through the client —
so a coordinator restart mid-login is survivable and there is no expiry sweep.

Two risks that come with the ceremony, accepted rather than fixed in v1 (there
is no rate limiting in the coordinator yet):

- **Quota exhaustion.** `/auth/device/start` is necessarily unauthenticated, so
  anyone who can reach it can burn the OAuth app's device-code rate limit and
  block logins. No credential is exposed.
- **Remote phishing** (RFC 8628 §5.4). An attacker starts a flow and
  social-engineers a victim into typing the `user_code`; the attacker's poll then
  returns a session token *as the victim*. This is inherent to every device flow
  — the mitigation is the warning GitHub shows on its own approval page, plus
  short session TTLs.

| Principal | Bootstrap | Ceremony |
|---|---|---|
| **User** (laptop) | `login` — GitHub device flow | browser, once |
| **Node, user present** | `share` — reuses the session to self-register | zero extra steps |
| **Node, headless** | `node up` prints a URL + code; a member runs `node approve <code>` | no token copy-paste |
| **Node, unattended** | pre-minted **auth key** (org-scoped, expiring, tagged) | one paste, revocable |
| **CI worker** | GH Actions workload OIDC, exchanged at `/auth/token`, plus a per-repo grant (§6.7) | zero secrets |
| **CI worker, no workload identity** | a `--purpose ci` **auth key** redeemed at `/auth/token` (§6.7, the weak path) | one paste, revocable |
| **Sandboxed agent** | *no enrollment* — lease-bound capability token | one command |

**Interactive node approval** (`node up` rung 3, §4.2) reuses this ceremony's
shape for a machine rather than a human, and inherits a sharper version of its
second risk. The mechanics: the machine posts to `/node/register/start`, prints
a ~40-bit Crockford-base32 `user_code` (`ABCD-1234`) and polls; a member runs
`probe-rs-fleet node approve ABCD-1234` from a machine where they are logged in,
which binds the pending row to **their** org and user; the machine's next poll
mints its node token through the same code path `share` uses, so the resulting
`node` row is identical. Three decisions and three accepted risks:

- **Approval is a CLI verb, *and now also* a browser form** — but not the one
  this bullet originally forbade. The original reason stands and is recorded in
  §4.2: the *device* flow has no cookie session, so a coordinator-served page
  driven by it could not know who was looking at it. What changed is that the
  coordinator gained a real browser session of its own (`docs/web-ui.md` D1,
  which reverses this section's "no browser session" premise and records its
  cost), so `POST /api/v1/nodes/pending/{code}` resolves its subject from that
  cookie and calls the same `decide_pending_node` the CLI route calls, with the
  same membership check and the same audit rows.

  `GET /node/approve` is **still** informational and **reflects nothing** — no
  code in the URL, no query parameter echoed — so it cannot become a
  confused-deputy surface, and the URL deployed agents print keeps its meaning.
  Phase 2 of `docs/web-ui.md` added one static paragraph linking it to
  `/ui/approve`, where the same JSON endpoint is driven from a real form behind
  the session; that is a link, not a form, and the page still renders
  byte-identically whatever the query string. Please do not "finish the job" by
  putting the form there.

  There is deliberately **no** browser listing of pending registrations:
  `pending_node.org_id` is `NULL` until approval binds it, so a listing could
  only be a cross-tenant index of every live code — which would turn the
  enumeration risk below from "guess ~40 bits" into "read the list"
  (`docs/web-ui.md` §3/§4). The phishing warning the CLI prints rides on the
  JSON `inspect` response for the same reason: with nothing to browse, that
  response is all the approver has.
- **Membership is sufficient to approve**, as it is to `share`, and the node is
  owned by the approver (`node.owner_user_id`).
- **Approval refuses to take over an existing node.** The requesting machine
  chooses its own `node_name` *before any org is known*, and `register_node_full`
  is an upsert, so approving a name the approver's org already uses would
  re-credential the running machine and knock it off the fleet. The handler (not
  just the CLI) refuses that with `409 node_name_taken` unless `--replace` is
  passed, and the approval output names the collision loudly.

Accepted risks, recorded rather than fixed:

- **Remote phishing** (RFC 8628 §5.4) again, and worse than for login: the
  approver grants *hardware access in their org to a machine they cannot see*,
  on the strength of a code somebody read out. Mitigations: the approval verb
  inspects first and prints the requested name, tags, adoption policy, source IP
  and age; it says in as many words that you cannot see the machine and should
  approve only an enrollment you started; confirmation defaults to **no** and a
  non-tty is refused rather than defaulted. Every field it prints comes from an
  unauthenticated request, so names and tags are charset-validated server-side
  and neutered again client-side — otherwise ANSI escapes in a name could
  repaint the warning itself.
- **Cross-tenant code enumeration.** An authenticated member who guesses a
  `user_code` can inspect, and approve into their own org, a registration
  somebody in another org started. Bounded by ~40 bits behind a 15-minute TTL
  (blind enumeration is infeasible even unthrottled), by every attempt being
  audited, and — the control that lets the *victim* notice rather than only an
  auditor afterwards — by the enrolling machine printing which org it landed in.
- **Unauthenticated database growth.** This is **not** covered by the device
  flow's quota-exhaustion bullet above, and conflating the two is how the gap
  would survive review: the device flow is *stateless*, whereas
  `/node/register/start` writes a row holding caller-chosen strings.
  `max_pending_nodes` (default 256) caps the live set and the TTL sweep reclaims
  it; there is no per-source throttle. The honest cost of the cap is that a full
  table refuses legitimate enrollments until abandoned rows age out.

**Auth keys are mintable by any member, over the API** (`POST /auth/keys`,
`probe-rs-fleet auth-key create|list|revoke`). This closes the last surviving
piece of the revision-1 operator-rooted funnel: minting used to require a shell
on the coordinator host, which a hosted customer does not have, so "node,
unattended" was unreachable for them at all. ("Node, headless" — §4.2 rung 3 —
now ships too, and is the better path when a human is available to approve; a
key is the right answer for a disk image.) Three decisions, recorded:

- **Membership is sufficient to mint and to list**, consistent with "membership
  is enough to add a node" in §6.5. A key grants nothing a member could not
  already do with `share`; it only lets them do it on a machine they are not
  sitting at.
- **A key can never exceed the caller's org**, structurally rather than by
  checking: the org is read from the authenticated session, and there is no org
  field on the wire and no `--org` flag.
- **API-minted keys must expire**, TTL capped at 30 days; `ttl_secs = 0` is a
  `400`. Auth keys are the weak link in the credential model — long-lived bearer
  secrets that end up in CI config and disk images. A forever-key minted from a
  shell is an operator's informed choice (`coordinator auth-key --ttl 0` still
  allows it); a hosted member's is not.

**Revocation follows the lease-ownership rule of §6.5:** the key's creator may
revoke it, and an org admin may revoke any of the org's keys — including the
shell-minted ones, whose `created_by` is `NULL` and which would otherwise be
unrevokable over the API. A prefix shorter than 8 hex characters is refused
before the delete, because the underlying `LIKE` on an empty prefix would match
every key in the org; an ambiguous prefix is a `409` that deletes nothing.

One exchange endpoint, several proofs. Note that **GitHub is two identity
systems**, and v1 needs both verifiers:

- *User login* is **OAuth2, not OIDC** — no discovery document, no ID token, no
  JWKS. The device flow yields an access token; identity comes from calling
  `GET /user`. Store `github_user_id` (the immutable numeric id), **never** the
  login name, which can be renamed and reused. Concretely: `user.id` and
  `org.id` are `gh-<github_user_id>`; `login` and `org.slug` are display columns
  (§4.1).
- *CI* is **real OIDC** — a signed JWT with a JWKS endpoint and claims
  `repository`, `repository_owner`, `ref`, `job_workflow_ref`. No secret ever
  enters the runner.

**CI trust rule (v1):** a workload token proves "a job in repo `owner/name` at
ref X". Mapping that to a fleet org requires an explicit **per-repo** grant.
`repository_owner` alone is deliberately *not* sufficient — a fork or a new repo
under the same owner must not inherit hardware access.

#### The laptop dual-role case (resolved)

A laptop is routinely both a user and a node. Revision 1 forced two unrelated
enrollments producing two unrelated identities (`alice` as a client CN,
`alice-laptop` as a pinned agent fingerprint) in two config trees. Revision 2:

- **Config is per fleet, not per role** (§4.1) — one file, an optional `[user]`
  table and an optional `[node]` table. A laptop has both.
- **The node is owned by the user** (`node.owner_user_id`), so "my laptop's
  boards" is expressible and revoking the user cascades sensibly.
- **The two credentials stay distinct.** The node token is machine-scoped and
  survives reboots; the session token is human-scoped and short-lived. Merging
  them would make a compromised Pi equivalent to a compromised you.
- **One command:** `probe-rs-fleet share` — "this machine now offers its probes
  to the fleet", using the login you already have. Self-approving: membership in
  the org the session authenticated into is sufficient, and is *checked* (a
  non-member is a 403 — `authz::require_role` denies one everywhere else, so a
  node created for one would be an orphan its owner could never use).

### 6.5 Authorization (new)

Revision 1 shipped **no authorization**. Concretely, any holder of any valid
client cert could `open_channel` on **another principal's lease** (the handler
took `_principal` unused, looked the board up by lease id, and minted a
capability token for it), extend or release anyone's lease, power-cycle any
board, and read the entire audit log. These are fixed as part of the subject
model, not as separate work.

The model, deliberately minimal:

- **Deny by default.** Every request resolves to a `Subject` and is checked
  against the target object's org before anything else.
- **Two roles per org**, `admin` and `member`. Membership alone is enough to add
  a node, to use the org's boards, and to mint an org-scoped auth key (decided;
  finer roles can come later without a data migration).
- **Ownership checks**, unconditionally: a lease may be extended, released, or
  channel-opened only by its holder (or an org admin). **Auth-key revocation
  over `POST /auth/keys` follows the same rule** (§6.4): the creator, or an org
  admin — the latter also covering keys minted from a shell, which have no
  recorded creator.
- **Grants** carry sharing: `grant { subject, selector, ops[], expires }`, where
  the selector is the existing tag/chip constraint language. `grant bob --select
  'tag=nrf52' --ops flash,attach` is the "give access to other people" path, and
  it is revocable and audited. Individual-board grants are a degenerate
  selector.
- **Delegation to a sandbox** is *not* a grant and creates no principal:
  `ctl delegate` leases a board as you and hands out only the **capability
  token** for that lease — narrow, expiring, revocable by releasing the lease.
  The crypto for this already exists (§6.3); only the command is new.

#### What shipped (grants, ACL evaluation, `ctl delegate`)

**One selector grammar, one reading of every term.** `id=<name>`,
`board=<model>`, `chip=<c>`, `tag=<t>`, and `a && b` conjunctions of tags,
parsed by a single function in `fleet-proto`. The sidecar's
`PROBE_RS_FLEET_SELECT`, `ctl lease <sel>`, `ctl delegate --select` and
`grant --select` are thin delegates with **no per-surface dialect**: a bare word
is a *tag* everywhere (so `ctl lease nrf52840-dk-3` is a tag selector and the
board is named `ctl lease id=nrf52840-dk-3`).

The word "board" means the board **model** — the board type a developer asks
for ("I need an nrf52840dk") — on every surface: the `board=` term, the
`sidecar --board` flag and `PROBE_RS_FLEET_BOARD`. It is *not* the chip: a
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
such a rule would reject working configs at selection time, far from the file. A
CI auth key's tags *are* charset-validated at mint, since redemption turns them
into a selector.

**Evaluation is a pure value object** (`fleet_core::access::Access`): ownership
(a member of the board's org) or a live grant, deny by default, with `now`
always a parameter — so the whole (subject, object, op) matrix is a
table-driven unit test. The tenancy fence **moved rather than weakened**: board
matching is now org-blind, and the org comparison lives in exactly one place,
`grant.org == board.id.org`. A grant issued in org A saying `tag=nrf52`
therefore cannot reach org C's identically tagged board.

**Grants attenuate the capability token.** The token minted for a lease carries
the grantee's effective ops, recomputed at every mint (lease and each channel
open) and never cached, so a narrowed or revoked grant bites on the next
channel open rather than at the end of the lease's TTL.

**What `--ops` actually enforces**, stated plainly because writing "the agent
enforces `--ops`" would be false for half the labels:

| op | enforced where |
|---|---|
| `attach` | agent, at data-channel open |
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
deliberate divergence from `POST /auth/keys`, where membership is enough to
mint. The two verbs have different blast radii: an auth key cannot exceed the
caller's own org, while a grant points *outward*, handing the org's hardware to
someone who is not in it at all. In a personal org you are the admin, so the
single-user story is unchanged. Grants must expire (the API refuses an unbounded
one), mirroring the auth-key TTL discipline: an unbounded share of somebody
else's hardware is exactly the artefact that outlives its reason.

**Revocation is creator-or-admin, and it is real.** The rule matches auth-key
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
so a key pasted out of `ctl list` works verbatim. The grammar lives on
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
  derives as `HMAC-SHA256(signing seed, "probe-rs-fleet/serve-token/v1" ‖ lease ‖
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
- Leases are now **org-scoped**, and the per-principal concurrency cap is keyed
  by `Subject` rather than by a bare string.
- Lease records are the natural basis for future metering (lease-seconds per
  org); no billing is built now, but the data is recoverable by construction.

### 6.7 CI: workload identity (revision 2)

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

The namespace nevertheless gets a **real `org` row**, of kind `system`, created
by migration 0007. Leaving it row-less is the tempting version and it does not
survive contact with the code: `core.rs::tear_down_lease` and `extend_lease`
both fall back to the *acting subject's* org when the board's org cannot be
resolved (a lease being released as its board goes away), and
`audit_log.org_id` is `NOT NULL REFERENCES org(id)`. A row-less namespace turns
that rare release/extend race into a foreign-key error surfacing as a
coordinator error instead of "no such lease". The row converts a scattered
invariant ("never write an org-scoped row keyed on a workload's namespace") into
a structural one, and costs nothing: nobody is ever a member of it. The name is
reserved at **both** creation paths — `Db::ensure_org` refuses it and
`CoordinatorConfig::validate` refuses `default_org = "gha"` — because a reserved
name only one of two paths respects is a trap for the next change.

A subject id containing a slash works with no schema change because
`SubjectKey::parse` splits at the *first* `/` and the *first* `:`, so
`gha/workload:ariel-os/ariel-os` round-trips exactly.

#### `repository_owner` is verified, recorded, and never consulted

This is the security-relevant decision of the whole path.

`repository_owner` is required as a claim and refused if absent, written to the
token row and into the audit detail — and it takes no part in any authorization
decision. Access needs an explicit **per-repo** grant
(`grant --repo owner/name`). A fork, or a newly created repo under a granted
owner, produces a different subject key, matches no grant, and is refused with
`403 no_grant`. There is deliberately no `--repo-owner` flag to type.

Repo strings are lowercased on both sides — grant creation and claim ingestion —
by one shared function (`fleet_proto::ids::normalise_repo`). GitHub repo names
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
| no `[github_actions]` table | `503 workload_oidc_unconfigured`, mirroring `device_flow_unconfigured` |
| any verification failure | a flat `401 invalid_grant` |
| verified token, no grant | `403 no_grant` |

Every verification failure — expiry, audience, issuer, signature, missing claim,
unknown `kid` — answers the same flat `401`, with the reason in the coordinator's
log and never in the body. No oracle.

`403 no_grant` is deliberately *not* folded into that: the credential **is**
valid, and conflating the two sends an operator hunting a signing problem when
the answer is `grant --repo`. It leaks only that a repo is not granted, which
that repo's own maintainers already know. The coordinator's log names the repo
and the owner beside it, so the "but I granted the org!" case is diagnosable in
one line.

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
`PROBE_RS_FLEET_QUEUE_WAIT` (client-side, default 300s; `0` restores the old
fail-fast behaviour). Only a wait that expires is an error. That is what lets a
matrix wider than the fleet run to completion instead of failing legs, so
`max-parallel` is now a throughput knob rather than a correctness requirement.
Since every job in a repo is the *same* subject, `max_concurrent_per_subject`
is still effectively a per-repo cap and a wide CI matrix still hits it — but it
now says so (`AtCap`) instead of reporting contention.
`docs/ci-github-actions.md` says all of this in the operator's vocabulary.

#### The verb surface behind `/client`, walked

The route allowlist now admits `Session` **and** `Workload` on `/client`;
`/agent` and `/auth/keys` stay Session/Node, so a CI job cannot enroll a node or
mint credentials. But a route allowlist is only a fence if the verbs behind the
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
construction. Beside it, each exchange writes one `workload.token.mint` audit
row **per granting org** (each of them is lending hardware to this job, and each
operator must be able to answer "who used what, for how long" from their own
audit log alone), whose detail carries repo, owner, ref, workflow, run id and
the matching grant ids. No billing is built.

#### The auth-key fallback, which is the weak path

A self-hosted Jenkins box has no workload identity to offer, and heterogeneous
runners are a stated requirement, so `auth_key` grew a `purpose` (`node` | `ci`)
and an `ops` column. `purpose` defaults to `node`, so no existing key changes
meaning — widening what an auth key means would silently have turned every
enrollment key in every deployment into a board-access credential.

Redeeming a `ci` key at `grant_type: workload_key` does **not** widen
`board_access`. It upserts an *ordinary grant* — the same row `grant --repo`
writes, evaluated by the same code and revocable by the same verb — to an
org-scoped subject `<org>/workload:key:<hash8>` (or
`<org>/workload:agent:<name>` for a key minted `--as <name>` — see below), and
then mints a workload
token. The grant's id is deterministic (`ci-<key hash prefix>`), so a multi-use
key redeemed by twenty runners upserts one row, one grant and one concurrency
budget; the `ci-` prefix is a namespace no human-created grant id can occupy,
since those are 32 random hex characters, which keeps `grant revoke <prefix>`
unambiguous between the two. That verb accepts the `ci-` spelling explicitly
(`ci-` plus at least 8 hex characters) — `grant list` prints these ids, and a
listing whose ids its own revoke verb rejects would be a dead end. Revoking the
**key** does the same teardown and more, since it takes the credential with it.

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

Both the subject (`key:<hash8>`) and the grant id (`ci-<hash[..29]>`) above are
functions of the *credential*. So rotating a key — mint a new one, retire the
old — produces a **new subject and a new grant row**: the audit trail forks, the
per-subject concurrency cap resets, and the old grant lingers. A long-running
agent or CI runner has no persistent identity at all.

`auth-key create --purpose ci --as <name>` gives it one. The name is stored in
`auth_key.subject_name`, and redemption then builds the subject
`<org>/workload:agent:<name>` and a grant id derived from `(org, name)`. Because
`upsert_grant` is keyed on the grant id, a re-minted key with the same `--as`
re-upserts the **same row**: same audit history, same concurrency budget, same
revocation handle. Nothing downstream changes — `board_access`, `Access`, the
scheduler and the audit log are all subject-key-generic, and `SubjectKey::parse`
splits at the *first* `:`, so `agent:<name>` round-trips exactly as
`key:<hash8>` does.

The name is validated at mint time (`normalise_agent_name`) with the same
discipline as `normalise_repo`: trimmed, **lowercased** — so a rotation typed
months later is the same identity rather than a silent fork — restricted to
`[a-z0-9._-]` starting with a letter or digit, and capped at 64 characters. The
charset is what makes a chosen name structurally unable to spell the
`key:<hash>` form (no `:`) or to be mistaken for a `gha/workload:owner/repo`
repo subject (no `/`). It is org-scoped, since the subject carries the org, so
two tenants may each have a `builder`.

**The grant id mixes the org into a digest, and that is not decoration.**
`grant.id` is a *global* `PRIMARY KEY`, and `upsert_grant`'s `ON CONFLICT(id)`
updates the selector, ops and expiry without touching `org_id`. An id spelled
from the name alone would therefore let org B's redemption silently rewrite org
A's grant row while leaving it owned by A — a cross-tenant write. So the id is
`ci-` plus 29 hex characters of `SHA-256(org, "agent:", name)`: globally unique,
inside the `ci-` namespace no human-created id occupies, and still **hex**, so
`grant revoke`'s ≥8-hex-character floor accepts it untouched. The cost is that
the id is opaque; the row's `subject` column, which `grant list` also prints,
shows `<org>/workload:agent:<name>` in clear text.

A named identity is also an ordinary grantee, so
`grant acme/workload:agent:builder --select …` works and gives it access beyond
what its redemption synthesises. Such a grant has an ordinary random id and is
*not* touched by the key-revocation cascade below, which keys on the synthesised
id — it is the one grant that survives.

**The trade, which is the whole point and a security-relevant surprise if
unstated: two live keys sharing an `--as` are one identity, and the grant
belongs to the identity, not to the key.** Revoking one of them tears down that
shared grant and every live lease held under the name — including another key's
runner, mid-job. It does not end the identity: a surviving key with the same
name re-creates the grant on its next redemption, and workload tokens already
minted stay **authenticated** for the rest of their TTL (nothing deletes
`workload_token` rows on revocation; the sweep only removes expired ones), so
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

`probe-rs-fleet agent login --fleet-url <url> --auth-key prffk1_… [--as <name>]`
closes that. It stores the durable key in the fleet file's `[agent]` table
(§4.1), and `ctl` and the `probe-rs` shim re-**redeem** it whenever the stored
token is within 60s of expiry.

**The mechanism is re-redemption, not refresh, and that distinction is what
keeps the earlier subsection literally true.** Nothing gained a refresh path;
`Refresh` is still session-only. Each renewal is an ordinary `workload_key`
exchange — the same request `ci login --auth-key` makes, verified the same way,
upserting the same grant row — which also explains why concurrency here needs no
locking: a multi-use key is never consumed (`consume_auth_key` stamps
`consumed_at` only for `single_use != 0`), so N processes renewing at once all
succeed and every token they mint stays valid. The only cost is churn, damped by
re-reading the fleet file before redeeming (§4.1).

**A single-use key is refused**, because in a sandbox with concurrent users it
breaks on the second *process*, not merely the second hour. Nothing on the wire
reveals single-use-ness — `TokenResponse` has no such field — so `agent login`
detects it by redeeming **twice**: a multi-use key yields two valid tokens (the
first is left orphaned until its TTL expires, one wasted `workload_token` row
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

The *cross-invocation* half: `fleet_sidecar::lease_store` persists a grant under
`$XDG_RUNTIME_DIR/probe-rs-fleet/leases.json` (0600, in a 0700 directory,
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
  `PROBE_RS_FLEET_NO_LEASE_CACHE` opt-out all release at exit exactly as before,
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
  split means it *waits* for a turn (bounded by `PROBE_RS_FLEET_QUEUE_WAIT`)
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

- `PROBE_RS_FLEET_BOARD` — board **model**: any idle board of that type
  (e.g. `nrf52840dk`), or
- `PROBE_RS_FLEET_ID` — one specific board, by node-local id
  (e.g. `nrf52840-dk-3`), or
- `PROBE_RS_FLEET_SELECT` — constraint expr (e.g. `tag=nrf52 && bluetooth`).
- `PROBE_RS_FLEET_TOKEN` / `…_COORDINATOR` — auth + endpoint.
- `PROBE_RS_FLEET_QUEUE_WAIT` — how many seconds to wait for a queued lease to
  be promoted before giving up (default 300; `0` = do not wait). A client-side
  patience bound, not a coordinator policy knob: how long *this* invocation is
  willing to sit in the queue is the caller's business (§6.6).
- Absent ⇒ sidecar falls back to local probe-rs (transparent local DX).
- Setting more than one of the three selector vars is `AmbiguousSelector`, not
  a precedence rule.

For interactive use the explicit subcommand also takes the selector as a flag:

```sh
probe-rs-fleet sidecar --select 'tag=nrf52840dk' -- list
probe-rs-fleet sidecar --board nrf52840dk -- run --chip nRF52840_xxAA app.elf
probe-rs-fleet sidecar --id nrf52840-dk-1 -- run --chip nRF52840_xxAA app.elf
```

- **Flag > env**, and a flag *replaces all three* selector vars (so `--select`
  next to a stale `PROBE_RS_FLEET_BOARD` is the flag, not an ambiguity error).
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

A declaration always beats an adoption for the same probe, and the agent
enforces that in one place (its board lookup consults `boards.toml` first), so
it is a structural property rather than a convention every call site has to
remember. The same precedence is applied by **name** at synthesis time: a probe
whose derived id collides with a declared `id` bound to a different serial is
not adopted at all. Reporting two boards under one name would have the
coordinator keep whichever it upserted last while the agent resolved the
declared one — so a lease taken out for the adopted probe would drive the
declared board's hardware.

**Declaring a board without hand-editing.** `probe-rs-fleet node board add`
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
probe-rs-fleet/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ fleet-proto/             # shared wire types + Subject/ids (no I/O)
│  ├─ fleet-core/              # Board/Lease/Policy domain + scheduler (pure, unit-testable)
│  ├─ fleet-tls/               # client trust config (WebPKI + optional pin); no client certs
│  ├─ fleet-auth/              # NEW: GitHub OAuth/OIDC verifiers, token mint/verify, grants
│  ├─ fleet-agent/            # probe-rs process control, USB power, boards.toml
│  ├─ fleet-coordinator/      # sqlite state, scheduler, authz, relay, HTTP/WS surface
│  ├─ fleet-sidecar/          # probe-rs CLI shim + relay client
│  └─ fleet-bin/              # single multi-role binary; thin dispatch
└─ docs/
```

`fleet-core` stays pure so the scheduler is testable without sockets or USB.
`fleet-auth` is likewise pure-ish (verification logic behind traits, HTTP calls
at the edges) so token and grant evaluation is unit-testable without a network.

## 10. Open questions / decisions to confirm

**Resolved (revision 1):**

- *probe-rs transport* = postcard-rpc 0.12 (confirmed from source). Data plane
  tunnels opaque postcard-rpc frames (§3).
- *"time-based"* = time-based **sharing**: extendable board claims across many
  probe-rs invocations, not lease-per-run (§6.6).
- *myelin* is **dropped**: postcard for both planes (§3).

**Resolved (revision 2 — this revision):**

- *Deployment model* = **hosted, multi-tenant**, behind an HTTPS reverse proxy.
- *Transport* = **WebSocket over HTTPS**, replacing the bespoke length-prefixed
  TCP protocol (§3.5).
- *Connection auth* = **bearer tokens**; the private CA, CSR issuance, client
  certs and cert pinning are **deleted** (§6.2).
- *Identity root* = **GitHub only** at v1 — OAuth2 device flow for users, GH
  Actions workload OIDC for CI (§6.4).
- *Tenancy* = every subject and object is org-scoped; a **personal org is
  auto-created on first login** (§6.1). The DB is **wiped**, not migrated.
- *Node registration* = **self-approving on membership**; no admin approval step
  at v1 (§6.4).
- *Probe adoption* = per-node policy, `auto` for personal nodes, `declared` for
  lab nodes (§4.2, §8).
- *Capability tokens* are unchanged and remain the sandbox-delegation mechanism
  (§6.3, §6.5).

**Still open:**

1. **Self-hosted TLS story.** A self-hosted coordinator without public DNS
   cannot get a publicly trusted certificate, so `fleet-tls` keeps an optional
   **pinned server-cert fingerprint** (`server_cert_sha256` in the fleet
   config) — the one surviving remnant of the deleted pinning code. Whether we
   also ship a self-hosting story beyond dev use is a **product** question, not
   an architectural one; keeping the coordinator a self-hostable artifact is
   cheap now and expensive to retrofit (NDA-bound customers may be structurally
   unable to point lab hardware at a third-party control plane).
2. **Does probe-rs's postcard-rpc server already expose remote probe/chip
   selection over the wire?** If yes, plain proxying is sufficient and the agent
   only manages process lifecycle + `--probe`. If not, file tasks against
   probe-rs (or myelin, per your offer). Needs a look at probe-rs's server impl.
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
4. **probe-rs process lifecycle.** Decided-ish: **one server process per board**,
   possibly per lease for isolation. Confirm per-lease vs per-board-reused.
5. **Sidecar install UX.** argv0 `probe-rs` shim on PATH vs explicit
   `fleet sidecar run -- …` wrapper. Which install story do you want?
6. **Where the hosted control plane runs.** Still open — but it no longer gates
   `login`: the device flow has no `redirect_uri`, so there is no callback
   origin to register and nothing is hardcoded (§6.4). The only hostname
   involved is the coordinator's own `public_url`, which is configuration.
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
