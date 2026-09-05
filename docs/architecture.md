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
  `agent`, `coordinator`, `sidecar`, `ctl`, plus the user verbs `login`,
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
| `GET /node/approve` | anyone | static page: what to run to approve one |
| `GET /healthz` | proxy | liveness |

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
bootstrap mechanism, `principal_from_cert`, `agent_id_from_cert` — is deleted.

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
refuses — a key that never expires.

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

[node]                 # present once `share` / `agent up` has run
node_token = "…"       # long-lived machine bearer, auto-rotating
node_id = "gh-4242/kaspar-laptop"
coordinator_token_pubkey = "…"   # verifies per-lease capability tokens
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
job). `--fleet <name>` / `PROBE_RS_FLEET` select among several fleets; `default`
is used otherwise. Credentials are stored `0600`; the two tokens stay **distinct**
by design (§6.4).

This replaces `agent.toml` and `client.toml` entirely — both files are deleted.
`AgentConfig` is no longer a file format at all: the `agent` role assembles it
from the fleet file's `[node]` table plus node-local settings.

Node-local, non-credential settings move to `~/.config/probe-rs-fleet/node/`
(`node.toml` for boards path / heartbeat / erase-on-release, `boards.toml` for
the inventory). They describe the *machine*, not the fleet, so they are not
per-fleet and are not duplicated when a machine joins a second one.

Credential env vars collapse to a single `PROBE_RS_FLEET_TOKEN`; the selector
vars (`PROBE_RS_FLEET_BOARD` / `_SELECT`) are unchanged. `PROBE_RS_FLEET_PROFILE`
is gone, replaced by `PROBE_RS_FLEET` (a fleet name).

**Writers are read-modify-write plus atomic rename.** A laptop has two
independent writers — `login` refreshing `[user]`, a running agent persisting a
rotated `[node]` token — so each patches only its own table. The residual race
is a lost update, recoverable by re-running the command; there is no file
locking in v1. The asymmetry justifies the cost: re-running `login` is a browser
tab, whereas clobbering a node credential is a physical visit to the Pi.

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
#      probe-rs-fleet agent up --fleet-url <url>       (on the Pi)
#      probe-rs-fleet node approve ABCD-1234           (on their laptop)
#    Nothing long-lived is copy-pasted, and the credential is bound at
#    approval time. For an unattended image, use 5b instead.
probe-rs-fleet agent up --fleet-url https://fleet.example.com

# 5b. …or, for an unattended image, a pre-minted auth key. Mint it on your
#     laptop with the login from step 2 — no shell on the coordinator:
probe-rs-fleet auth-key create --tag lab --tag nrf52 --ttl 24h
probe-rs-fleet agent up --auth-key prffk1_…
#     Self-hosted, or air-gapped, or for a key that never expires, the same
#     thing from a shell on the coordinator host:
probe-rs-fleet coordinator auth-key --org acme --tag lab --ttl 24h

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


### 4.2 `agent` (Raspberry Pi)
Owns local probes. Reconciles discovered probes against `boards.toml`.

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
>   deliberately keep the loopback-TCP model: 0.32's `run_unix()` ignores
>   `config.users` entirely — no challenge/token auth at all, only `0o660` fs
>   permissions — so adopting it would silently remove our per-board
>   `ProbeAccess::Allow` fence. Tracked as issue #297.)*
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
  Per-board (reused across a holder's many invocations), recycled on release
  for cleanup. This matches time-based sharing (§6).
  - **Token wiring (end-to-end, zero protocol change):** the per-board serve
    user `token` in `.probe-rs.toml` is the **hex of the fleet capability
    token**. The sidecar already sets `PROBE_RS_REMOTE_TOKEN = hex(grant.token)`
    and the agent receives those exact bytes as `token_wire` on `OpenSession`,
    so the two ends authenticate against the same value with no new wire field.
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

Agent also owns **USB power** behind a `PowerControl` trait: `uhubctl` (per-hub
port), GPIO relay, or `none`. Used for post-lease cleanup and fault recovery,
and exposed explicitly via `ctl`.

#### Config & scaffolding (`agent up`, revision 2)

The node's credential lives in the **per-fleet config** (§4.1); `agent.toml` is
deleted. Node-local settings live at `~/.config/probe-rs-fleet/node/`
(`node.toml`, `boards.toml`) — they describe the machine, not the fleet.

`probe-rs-fleet agent up` registers this machine as a node and starts serving.
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
> is a **CLI verb, not a browser form**, and that is a decision rather than an
> unfinished edge: `login` is the GitHub *device* flow, which by design has no
> `redirect_uri` and no cookie session (§6.4), so a page served by the
> coordinator cannot know who is looking at it. Building one would mean an OAuth
> redirect flow plus cookies in the coordinator, which contradicts §6.4 and
> reopens §10 Q6. `GET /node/approve` is therefore an *informational* page that
> says what to run.
>
> The design deliberately does not foreclose a real browser flow later.
> Approval is keyed by `user_code` and is a pure function of `(code, decision,
> authenticated user)`, factored so that a future cookie-authenticated handler
> resolves its subject its own way and calls the same function; the node-side
> wire contract (`start` / `poll`) never learns which mechanism approved it, so
> adding one is additive and deployed agents keep working; and the page that
> would grow the form already exists at the URL agents already print.
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
> `share` is `agent up`'s rung 2 as a standalone verb, and does **not** start
> the agent: it writes the credential and the node-local settings, and its
> summary points at `probe-rs-fleet agent`.

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
coordinator will adopt; re-running `share` / `agent up --adopt …` does. (Having
the coordinator push the policy down the established connection, as it does for
node tokens, is an obvious follow-up and deliberately not built here.)

**What an adopted board looks like.** Its id is derived from the probe alone
(`{product-slug}-{serial}`, or `probe-{vid}{pid}-{serial}` where the probe
reports no product), so it survives a restart and a reordered `probe-rs list` —
a lease selector names that id. Its tags are the probe type plus a literal
`auto`. Its `chip` is **empty**, because `probe-rs list` reports the probe and
not the target attached to it; the honest consequence is that `ctl lease
--select 'chip=…'` will not match an adopted board until `boards.toml`
annotates it. Two probes are never adopted: one that is `inaccessible` (the
lease would fail at `probe-rs serve` spawn time) and one reporting no serial
(which can be neither stably named nor fenced with `ProbeAccess::Allow`).

**Live discovery.** None of this means anything without a node that
re-enumerates: the agent runs a discovery pass every `discovery_secs` (default
30) and reports a new inventory **only when it changed**, so a quiet fleet stays
quiet. An enumeration failure keeps the previous inventory and does not drop the
connection — a transient USB or `probe-rs` hiccup taking every board offline
would be far worse than a stale snapshot.

**Unplugging is a report, not an absence.** A board leaves the scheduler only
via an explicit `Offline` status, never by going missing from a report — nothing
on the coordinator prunes a board an inventory failed to mention. That falls out
for a *declared* board (its `boards.toml` entry is still there to report as
offline), but an adopted board has no declaration, so the agent remembers what
the previous pass adopted and emits an offline tombstone for anything that has
since gone. Without it an unplugged laptop board would sit in the scheduler as
`Idle` forever: `ctl list` would show it, a lease against it would be *granted*
and a capability token minted, and the agent would refuse at the last hop. A
laptop is the machine where probes are unplugged several times a day, so this is
the common path.

The tombstone is honoured whatever the node's policy currently says — removing a
board is never a tenancy risk, and a node whose policy was flipped `auto` →
`declared` must still be able to retire what it adopted while it was `auto`.


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

#### Credentials (revision 2)

ctl and the sidecar both read the **`[user]` session** from the per-fleet config
(§4.1) — or, in CI, a token exchanged from a workload OIDC credential. The
revision-1 arrangement (a shared client certificate, discovered through two
different sets of env var names, bridged by the shim) is deleted along with the
rest of the client-cert model.

Resolution precedence is **explicit flag / env var > fleet config**. The
selector env vars (`PROBE_RS_FLEET_BOARD` / `_SELECT`) are unchanged; the
credential env vars collapse to a single `PROBE_RS_FLEET_TOKEN`.

**A sandboxed agent is never given these credentials.** It receives a
lease-bound capability token instead (`ctl delegate`, §6.5).


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
auth_key { org_id, key_hash, tags[], single_use, expires, created_by }
```

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

**No callback origin is involved.** The device flow (RFC 8628) has no
`redirect_uri` at all, so §10's unresolved "where does the hosted control plane
run" question does not gate login and nothing hardcodes a hostname. Register the
OAuth app with **Device Flow enabled**; there is no callback URL to fill in.

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
| **Node, headless** | `agent up` prints a URL + code; a member runs `node approve <code>` | no token copy-paste |
| **Node, unattended** | pre-minted **auth key** (org-scoped, expiring, tagged) | one paste, revocable |
| **CI worker** | GH Actions workload OIDC, exchanged at `/auth/token`, plus a per-repo grant (§6.7) | zero secrets |
| **CI worker, no workload identity** | a `--purpose ci` **auth key** redeemed at `/auth/token` (§6.7, the weak path) | one paste, revocable |
| **Sandboxed agent** | *no enrollment* — lease-bound capability token | one command |

**Interactive node approval** (`agent up` rung 3, §4.2) reuses this ceremony's
shape for a machine rather than a human, and inherits a sharper version of its
second risk. The mechanics: the machine posts to `/node/register/start`, prints
a ~40-bit Crockford-base32 `user_code` (`ABCD-1234`) and polls; a member runs
`probe-rs-fleet node approve ABCD-1234` from a machine where they are logged in,
which binds the pending row to **their** org and user; the machine's next poll
mints its node token through the same code path `share` uses, so the resulting
`node` row is identical. Three decisions and three accepted risks:

- **Approval is a CLI verb, not a browser form**, for the reason §4.2 records:
  the device flow has no cookie session, so a coordinator-served page cannot
  know who is looking at it. `GET /node/approve` is informational and
  **reflects nothing** — no code in the URL, no query parameter echoed — so it
  cannot become a confused-deputy surface.
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

**One selector grammar, extended by one term.** `board=<name>`, `chip=<c>`,
`tag=<t>`, and `a && b` conjunctions of tags, parsed by a single function in
`fleet-proto`. The sidecar's `PROBE_RS_FLEET_SELECT` and `ctl lease <sel>` are
thin delegates that differ only in what a *bare* word means — a tag for the
former, a board for the latter, which is a real difference between the two
surfaces rather than an accident. `board=<name>` is the individual-board grant:
a degenerate selector, not a special case. A grant stores the **canonical
rendering** (`Constraint`'s `Display`) and evaluation re-parses it, so a grant's
meaning never depends on which CLI wrote it; a row that will not re-parse is
dropped **closed**, never widened into a match-anything. An empty expression is
refused at every entry point, because an empty tag set matches every board.

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
covered by a second overlapping grant. The honest limit: an already-minted
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
(`state.rs::node_id_for` builds `AgentId("{org}/{name}")`, so the same machine
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
must not mistake a queue slip for a board.

**One data-plane token, carried explicitly.** `CoordToSidecar::ChannelOpened`
now carries the exact capability-token bytes the coordinator sent the node, and
that is what the sidecar exports as `PROBE_RS_REMOTE_TOKEN`. Previously the
sidecar exported the *lease grant's* token and the two matched only by
coincidence — same fields, deterministic ed25519 — a coincidence that an
`extend` already broke (it rewrites the expiry the channel mint reads) and that
attenuation breaks by construction. The wire field removes the whole class of
"two mints must be byte-identical" bugs. Protocol 6 → 7.

### 6.6 Lease lifecycle (unchanged)

- `request{constraints, duration, priority}` → `Leased{board, node, channel,
  token, expires}` or `Queued`. Heartbeat renews; missed heartbeats free the
  board and trigger node cleanup.
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
as a flake.

#### A workload's lease is clamped to CI priority

Whatever priority the request carries, a `SubjectKind::Workload` lease request
is clamped to `Priority::Ci`. §6.6's fairness ordering is "interactive dev >
nightly CI > soak" and priority is a plain wire field, so without the clamp a CI
job outbids a human at a desk by setting it. This is not an edge case: the
sidecar sends `Priority::Interactive` unconditionally, so the clamp fires on
*every* CI lease. `Policy::max_duration_ci` then applies to it, and extension
inherits the clamp for free — `Scheduler::extend_lease` re-derives the duration
from the **recorded** priority, so there is deliberately no second guard in
`extend_lease`.

The clamp orders contention; it does not make contention painless. A workload
whose request finds no free board is `Queued` like anybody else, and the sidecar
turns that into a hard error rather than waiting — a build step cannot sit on a
queue slip the way a human at `ctl lease` can. Since every job in a repo is the
*same* subject, `max_concurrent_per_subject` is effectively a per-repo cap and a
wide CI matrix hits it. `docs/ci-github-actions.md` says so in the operator's
vocabulary.

#### The verb surface behind `/client`, walked

The route allowlist now admits `Session` **and** `Workload` on `/client`;
`/agent` and `/auth/keys` stay Session/Node, so a CI job cannot enroll a node or
mint credentials. But a route allowlist is only a fence if the verbs behind the
route have been walked, so they were:

| verb | gate | workload |
|---|---|---|
| `Lease` / `Extend` / `Release` / `OpenChannel` / `CloseChannel` | `board_access` / `require_lease_control` | allowed — this is the CI story |
| `ListBoards` / `Who` | access-scoped | allowed |
| `Logs`, `GrantCreate` | `require_role(Admin)` | denied |
| `GrantList` / `GrantRevoke` | `require_role(Member)` | denied |
| **`Delegate`** | `board_access` **alone** | **explicitly refused** |

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
org-scoped subject `<org>/workload:key:<hash8>`, and then mints a workload
token. The grant's id is deterministic (`ci-<key hash prefix>`), so a multi-use
key redeemed by twenty runners upserts one row, one grant and one concurrency
budget; the `ci-` prefix is a namespace no human-created grant id can occupy,
since those are 32 random hex characters, which keeps `grant revoke <prefix>`
unambiguous between the two.

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

- An explicit claim (`fleet ctl lease <board> [--duration]`, or first use under
  a selector) holds the board for the principal with an **extendable timeout**.
- Each subsequent vanilla `probe-rs …` from that workstation **reuses the
  existing lease** instead of re-queuing (sidecar caches `{board, lease, token}`
  keyed by selector + principal).
- Heartbeats / activity **extend** the timeout; an idle lease expires after its
  TTL and the board returns to the pool (agent runs cleanup: power-cycle,
  optional erase).
- Explicit `fleet ctl release` frees it immediately.

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

- `PROBE_RS_FLEET_BOARD` — explicit board id, or
- `PROBE_RS_FLEET_SELECT` — constraint expr (e.g. `tag=nrf52 && bluetooth`).
- `PROBE_RS_FLEET_TOKEN` / `…_COORDINATOR` — auth + endpoint.
- Absent ⇒ sidecar falls back to local probe-rs (transparent local DX).

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
