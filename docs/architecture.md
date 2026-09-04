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
> the `coordinator enroll` → `agent init` / `ctl init` token dance is **dropped**,
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
| `POST /auth/device/*` | `login` | GitHub device-flow start/poll (§6.4) |
| `POST /auth/token` | CI, nodes | token exchange (workload OIDC, auth keys) |
| `GET /healthz` | proxy | liveness |

**Keepalive is now load-bearing.** A proxy in front means idle WebSockets are
reaped on a timeout we do not control, so the node connection must run
ping/pong keepalive, and the existing reconnect backoff stops being a nicety.

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
  reachable origin, used for OAuth redirect construction), the GitHub OAuth app
  credentials, and the lease policy.

It no longer generates a client CA, a server cert, or a server key: TLS is the
reverse proxy's job (§3.5). `init` refuses to overwrite existing files unless
`--force` is passed.

**`coordinator enroll` is demoted.** It survives only as the **auth-key minter**
for unattended nodes (§6.4) and as an admin escape hatch; it is no longer on the
normal path for either users or CI. Its old CSR-issuing behaviour is gone.

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
org = "kaspar"

[node]                 # present once `share` / `agent up` has run
node_token = "…"       # long-lived machine bearer, auto-rotating
node_id = "kaspar-laptop"
```

A laptop that both consumes and provides simply has **both tables**. A headless
Pi has only `[node]`. A CI runner has neither (it exchanges a workload token per
job). `--fleet <name>` / `PROBE_RS_FLEET` select among several fleets; `default`
is used otherwise. Credentials are stored `0600`; the two tokens stay **distinct**
by design (§6.4).

This replaces `agent.toml`'s credential fields and the whole of `client.toml`.
Node-local, non-credential settings (`boards.toml`, power config) stay where
they are.

#### End-to-end deployment flow (revision 2)

```sh
# 1. On the coordinator host: scaffold signing keys + config.
probe-rs-fleet coordinator init --public-url https://fleet.example.com
#    Set GitHub OAuth app id/secret in coordinator.toml, then start it
#    behind your HTTPS reverse proxy.
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

# 5. A headless Pi in the lab: prints a URL + code; approve it in your browser.
probe-rs-fleet agent up --fleet-url https://fleet.example.com

# 5b. …or, for an unattended image, a pre-minted auth key:
probe-rs-fleet coordinator auth-key --org acme --tags lab,nrf52 --ttl 24h
probe-rs-fleet agent up --auth-key prffk1_…

# 6. Give a colleague access to some of your boards.
probe-rs-fleet grant bob --select 'tag=nrf52' --ops flash,attach --until 2026-12-31

# 7. Hand a sandboxed agent one board, with no fleet identity of its own.
probe-rs-fleet ctl delegate --select 'tag=nrf52' --ops flash,attach --ttl 2h
#    → prints a lease-bound capability token; nothing else is granted.
```

To enroll an agent, ctl user, or sidecar, use the **bootstrap-token** flow. The
token is a one-time *bootstrap* credential; **runtime authentication stays mTLS,
unchanged** — the token only buys the client a CA-signed client certificate.

1. **`probe-rs-fleet coordinator enroll <principal-id> --kind agent|client
   [--ttl <secs>]`** (run on the coordinator host). This mints a random
   single-use secret, stores only its SHA-256 hash in the coordinator database
   (`enroll_tokens`, single-use + TTL'd), and prints **one opaque,
   copy-pasteable token string** plus a ready-to-paste `agent init` / `ctl
   init` command. The token encodes three things:
   1. the coordinator address (`host:port`) clients should **dial**,
   2. the SHA-256 of the coordinator's server certificate (for bootstrap
      server-cert pinning — see below), and
   3. the random single-use secret (the credential).
   The token is a transport blob, not signed; the secret IS the credential,
   validated server-side by hash lookup.
   - **Advertised address.** The embedded `host:port` is the address agents /
     clients dial, which is often *not* the `listen_addr` (typically the
     wildcard `0.0.0.0:7000` / `[::]:7000`, which is not routable from another
     host). `enroll` resolves the embedded address as: `--coordinator-addr
     <host:port>` override > `advertise_addr` in `coordinator.toml` >
     `listen_addr` fallback. If the resolved address is a wildcard /
     unspecified IP it is **rejected with a hard error** rather than silently
     embedding an undialable `0.0.0.0` — set `advertise_addr` or pass
     `--coordinator-addr` with the coordinator's LAN / public address. (A
     hostname is always accepted; only `0.0.0.0` / `::` are treated as
     wildcards.)
   - `--kind agent`: the issued cert's fingerprint is **auto-pinned** in the
     coordinator database (`agent_pins`) on enrollment, so the manual
     `[pinned_agents]` edit is unnecessary.
   - `--kind client` (ctl / sidecar users): no pinning needed (non-agent
     principals are treated as sidecars).
2. **Redeem the token** on the target host with `agent init` / `ctl init
   --token <t> --profile <p>` (below). The client opens a bootstrap TLS
   connection to the coordinator (verifying the server leaf against the token's
   hash via a custom pinning verifier — **not** blind trust-on-first-use),
   generates a keypair + CSR **locally** (the private key never leaves the
   host), sends an `EnrollRequest { secret, csr_pem }`, and receives back
   `{ client_cert_pem, ca_cert_pem, coordinator_token_pubkey }`.

The coordinator's TLS listener allows **optional** client auth: a connection
that presents **no** client cert may ONLY perform the enroll exchange (it can
never reach the runtime agent/sidecar dispatch); a connection with a verified
client cert routes to the existing runtime mTLS path. This mirrors hydra's
branch on client-cert presence on a single listener — no separate bootstrap
port.

The issued-cert fingerprint is the **lowercase hex SHA-256 of the certificate
DER, with no `sha256:` prefix and no colons** (exactly what
`fleet_tls::cert_fingerprint` produces). A fully-commented reference config
lives at `examples/coordinator.toml`.

#### End-to-end deployment flow

A clean setup from scratch:

```sh
# 1. On the coordinator host: scaffold CA + signing seed + server cert + config.
#    Use --hostname / --ip so the server cert SANs cover the address clients
#    will dial; set `advertise_addr` in coordinator.toml (or pass
#    --coordinator-addr to `enroll`) to that same dialable address.
probe-rs-fleet coordinator init --hostname coordinator.example --ip 192.168.1.10

# 2. Start the coordinator.
probe-rs-fleet coordinator

# 3a. Mint a one-time bootstrap token for an agent (auto-pinned on enrollment).
#     The embedded address must be DIALABLE: because listen_addr defaults to the
#     wildcard 0.0.0.0:7000, pass --coordinator-addr (or set advertise_addr in
#     coordinator.toml) — otherwise `enroll` errors instead of embedding 0.0.0.0.
probe-rs-fleet coordinator enroll rpi-lab-1 --kind agent --coordinator-addr 192.168.1.10:7000
#   → prints: prffe1_…  (addr + server-cert hash + single-use secret)

# 3b. Mint a one-time bootstrap token for a ctl / sidecar user.
probe-rs-fleet coordinator enroll alice --kind client --coordinator-addr 192.168.1.10:7000
#   → prints: prffe1_…

# 4. Redeem each token on its target host (runtime stays mTLS):

#   On the agent (Raspberry Pi): pinned bootstrap TLS → local CSR → CA-signed cert.
probe-rs-fleet agent init --profile lab1 --token prffe1_…
# edit ~/.config/probe-rs-fleet/agent/lab1/boards.toml, then:
probe-rs-fleet agent --profile lab1     # connects via mTLS with the issued cert

#   On the workstation / CI host:
probe-rs-fleet ctl init --profile ci --token prffe1_…
probe-rs-fleet ctl --profile ci list    # authenticates via client.toml (mTLS)
# the `probe-rs` sidecar shim uses the same per-profile client.toml automatically
# (select the profile with PROBE_RS_FLEET_PROFILE).
```


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

The node's credential lives in the **per-fleet config** (§4.1), not in a
per-profile `agent.toml`. Node-local settings (`boards.toml`, power control)
remain at `~/.config/probe-rs-fleet/node/`.

`probe-rs-fleet agent up` registers this machine as a node and starts serving.
It obtains a node token by whichever of these applies, in order:

1. **An existing `[node]` credential** in the fleet config — just reconnect.
2. **An existing `[user]` session** (i.e. `login` has run here) — self-register
   silently against your org. This is what `share` does; membership is
   sufficient, no admin approval (decided).
3. **Interactive approval** — print a URL + short code; the user approves in a
   browser on any machine. This is the headless-Pi path, and it replaces the
   copy-paste of a bootstrap token.
4. **An auth key** (`--auth-key`) — org-scoped, expiring, optionally
   single-use, carrying default tags. This is the unattended/image path.

The node token is long-lived but **rotating**: the coordinator can issue a
replacement over the established connection, so a leaked token has bounded
value and revocation is a `DELETE` in the `node` table rather than a CRL.

**Probe adoption is now per-node policy, not a global gate.** Revision 1 made
every probe wait for a `boards.toml` declaration, which is right for a lab and
pure friction for a laptop:

- `adopt = "auto"` (default for nodes created by `share`): discovered probes are
  adopted into the owning org automatically, with tags inferred from probe and
  chip. Plug in a board, it is usable.
- `adopt = "declared"` (default for auth-key / lab nodes): unknown probes are
  reported but not leasable until declared, so CI gets stable ids and no
  surprises.

`boards.toml` therefore becomes **annotation and override** — stable ids, power
wiring, curated tags — rather than admission control.


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
| Workload (CI) | exchanged from a GH Actions OIDC JWT | one job | expiry / grant removal |

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

| Principal | Bootstrap | Ceremony |
|---|---|---|
| **User** (laptop) | `login` — GitHub device flow | browser, once |
| **Node, user present** | `share` — reuses the session to self-register | zero extra steps |
| **Node, headless** | `agent up` prints URL + code; approve in a browser | no token copy-paste |
| **Node, unattended** | pre-minted **auth key** (org-scoped, expiring, tagged) | one paste, revocable |
| **CI worker** | GH Actions workload OIDC, exchanged at `/auth/token` | zero secrets |
| **Sandboxed agent** | *no enrollment* — lease-bound capability token | one command |

One exchange endpoint, several proofs. Note that **GitHub is two identity
systems**, and v1 needs both verifiers:

- *User login* is **OAuth2, not OIDC** — no discovery document, no ID token, no
  JWKS. The device flow yields an access token; identity comes from calling
  `GET /user`. Store `github_user_id` (the immutable numeric id), **never** the
  login name, which can be renamed and reused.
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
  to the fleet", using the login you already have.

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
  a node and to use the org's boards (decided; finer roles can come later
  without a data migration).
- **Ownership checks**, unconditionally: a lease may be extended, released, or
  channel-opened only by its holder (or an org admin).
- **Grants** carry sharing: `grant { subject, selector, ops[], expires }`, where
  the selector is the existing tag/chip constraint language. `grant bob --select
  'tag=nrf52' --ops flash,attach` is the "give access to other people" path, and
  it is revocable and audited. Individual-board grants are a degenerate
  selector.
- **Delegation to a sandbox** is *not* a grant and creates no principal:
  `ctl delegate` leases a board as you and hands out only the **capability
  token** for that lease — narrow, expiring, revocable by releasing the lease.
  The crypto for this already exists (§6.3); only the command is new.

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
(§6.1).

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
6. **Where the hosted control plane runs**, and therefore the GitHub OAuth app's
   registered callback origin. Must be answered before `login` hardcodes
   anything.
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
