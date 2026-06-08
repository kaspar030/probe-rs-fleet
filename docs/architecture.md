# probe-rs-fleet — Architecture

Status: **accepted; scaffolding**. Decision log: myelin dropped — single-stack
postcard-rpc for both data and control planes (§3). This document records the
agreed shape of the system and the decisions still open. It is deliberately concrete about how the
pieces map onto [`myelin`](../../myelin) and the real `probe-rs` CLI surface
that [ariel-os / laze](../../ariel-os/laze-project.yml) emits.

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
   dev workstation / CI                 coordinator (1 node)              Raspberry Pi "agent"
 ┌───────────────────────┐           ┌──────────────────────┐         ┌──────────────────────────┐
 │  laze … run           │           │  sqlite state        │         │  boards.toml             │
 │    │                  │           │  scheduler / leases  │         │  USB power (uhubctl/gpio)│
 │    ▼ (real probe-rs   │  mTLS +   │  auth / quotas       │  mTLS + │  probe-rs (as library OR │
 │     CLI args)         │  myelin   │  audit log           │  myelin │   child server process)  │
 │  fleet sidecar  ──────┼──────────▶│  RELAY (data plane)  │◀────────┼──  fleet agent           │
 │  (probe-rs shim)      │  (TLS     │                      │ (agent  │                          │
 └───────────────────────┘  dial-in) └──────────────────────┘ dials   └──────────────────────────┘
                                                               OUT)
```

Key constraints that drove this shape:

- **No direct workstation→agent connection.** All traffic relays through the
  coordinator. Agents live behind NAT on lab networks; the coordinator is the
  only publicly reachable node.
- **Agents dial out.** The agent opens a persistent mTLS connection *to* the
  coordinator. Over that one connection the coordinator can also call *into*
  the agent (see §5). No inbound ports on the Pis.
- **Single multi-role binary** (`probe-rs-fleet`), role chosen by subcommand:
  `agent`, `coordinator`, `sidecar`, `ctl`.

## 3. Transport: postcard-rpc data plane, typed control plane, over mTLS (decided)

Key fact (confirmed by reading the source): **probe-rs's client/server mode is
[`postcard-rpc`](https://docs.rs/postcard-rpc) 0.12.** That crate abstracts its
wire behind `WireTx` / `WireRx` / `WireSpawn` traits — its stock host transports
are all point-to-point (`raw_nusb`, `serial`, `webusb`), but
`HostClient::new_with_wire(tx, rx, spawn)` accepts *any* wire impl. This is the
seam we build on. It splits the problem cleanly into two planes:

### Data plane — opaque postcard-rpc tunnel

The sidecar speaks **vanilla probe-rs**. probe-rs's postcard-rpc frames are
length-delimited postcard messages over a byte stream. We do **not** parse or
re-implement them — we tunnel the raw frames:

```
  sidecar's probe-rs client  ──postcard-rpc frames──▶  [ mTLS to coordinator ]
      ──relay──▶  [ mTLS to agent ]  ──▶  agent's probe-rs server
```

The coordinator forwards opaque bytes on a leased channel; it never decodes
probe-rs traffic. Whether the sidecar plugs in at the `WireTx`/`WireRx` level
(a custom postcard-rpc wire that points at the relay) or simply byte-splices a
local socket is an implementation detail — both carry the same frames.

### Control plane — leases, inventory, auth, power, heartbeats

Small typed request/response + a few server→client pushes. **Two candidates,
and this is now the main open transport decision (was: "is myelin needed?"):**

- **Option A — myelin.** `DuplexStreamTransport` gives genuine bidirectional
  call-and-serve over one stream (agent dials out, coordinator calls back), with
  `api_id` multiplexing so several service traits and the opaque data-plane
  channel share one mTLS connection. Clean fit; one more dependency.
- **Option B — reuse postcard-rpc for control too.** postcard-rpc has Endpoints
  (req/resp) *and* Topics with `ToServer`/`ToClient` direction, so server→client
  push (coordinator→agent commands) is expressible via topics. Using it for both
  planes means **one RPC stack, and myelin can be dropped entirely.** Costs:
  topic-based "server calls client" is more awkward than myelin duplex, and we'd
  hand-roll the multiplexing of control + data over the single TLS pipe.

**Recommendation:** prototype Option B first (drop myelin) — the data plane is
*already* postcard-rpc, so using it for control keeps the stack singular and the
binary smaller. Fall back to myelin (Option A) only if duplex control ergonomics
or multiplexing get painful. Either way, the data plane is unchanged.

> **DECISION (accepted):** myelin is dropped. We use **postcard-rpc for both
> planes**. Coordinator→agent commands ride `ToClient` topics over the agent's
> single dial-out connection; the opaque data channel is multiplexed over the
> same TLS pipe. Revisit only if control ergonomics force it.

### mTLS is an I/O-layer concern in both options

`tokio_rustls::TlsStream` is `AsyncRead + AsyncWrite`. postcard-rpc's wire and
myelin's `tokio_io` adapter both sit on top of that stream, so **mTLS needs no
change to either RPC library.** We own a `fleet-tls` crate for rustls config and
cert pinning.

mTLS policy:

- Coordinator presents a server cert; agents and sidecars present client certs.
- Agent identity is pinned in coordinator config (cert fingerprint → agent id).
- Workstation/CI identity is pinned to a user/service-account principal.
- The TLS client-cert authenticates the *connection*; per-board capability is a
  separate short-lived token (see §6).

## 4. Roles

### 4.1 `coordinator`
Central daemon, single node, sqlite (via `sqlx`) for state. Responsibilities:

- **Inventory:** reconcile board reports from all agents into one fleet view.
- **Scheduling & leases:** match constraint requests to idle boards; queue when
  none free; lease TTL + heartbeat renewal; fairness/quotas.
- **Auth:** verify mTLS principals; issue per-lease capability tokens.
- **Relay (data plane):** splice a sidecar's probe-rs session to the owning
  agent. The coordinator does **not** parse probe-rs traffic; it forwards
  opaque framed payloads on a leased channel. Restartable without dropping
  active TLS sessions within lease TTL is a goal, not a v1 guarantee.
- **Audit log:** who leased what, when, power events, faults.

Does **not** touch USB.

#### Config & scaffolding (`coordinator init`)

The coordinator reads a TOML config. By default it is discovered at the XDG
path `~/.config/probe-rs-fleet/coordinator.toml`
(`$XDG_CONFIG_HOME/probe-rs-fleet/coordinator.toml`); `--config` /
`PROBE_RS_FLEET_CONFIG` override it. Generated key/cert/seed material and the
SQLite database default to the data dir `~/.local/share/probe-rs-fleet/`
(`$XDG_DATA_HOME/probe-rs-fleet/`). The agent config follows the same scheme at
`~/.config/probe-rs-fleet/agent.toml` (`PROBE_RS_FLEET_AGENT_CONFIG`).

`probe-rs-fleet coordinator init` scaffolds a ready-to-run coordinator on a
clean machine:

- generates a fresh ed25519 capability-token signing seed
  (`<data>/signing.seed`, 64 hex chars, `0600`);
- generates a development client CA (`client-ca.pem` + `client-ca-key.pem`) and
  a coordinator server cert/key (`coordinator-cert.pem` /
  `coordinator-key.pem`) signed by it, with SANs from `--hostname` / `--ip`
  (default `localhost` / `127.0.0.1`);
- writes a populated `coordinator.toml` pointing at all of the above
  (`listen_addr = "0.0.0.0:7000"`, default policy, empty `[pinned_agents]`).

Keys are written `0600`. `init` refuses to overwrite existing files unless
`--force` is passed; `--config-dir` / `--data-dir` override the target
directories. Afterwards, `probe-rs-fleet coordinator` (no `--config`) loads the
generated config and starts listening.

To enroll an agent: issue it a client certificate from the generated CA,
compute the cert's fingerprint — the **lowercase hex SHA-256 of the certificate
DER, with no `sha256:` prefix and no colons** (exactly what
`fleet_tls::cert_fingerprint` produces) — and add
`"<fingerprint>" = "<agent-id>"` under `[pinned_agents]`. A fully-commented
reference config lives at `examples/coordinator.toml`.

### 4.2 `agent` (Raspberry Pi)
Owns local probes. Reconciles discovered probes against `boards.toml`.

> **Updated by investigation (task #1710, probe-rs 0.31.0):** The server is
> `probe-rs serve`. It takes **no `--probe` / `--chip`** — it exposes *all*
> local probes and the connecting client selects probe + chip **in-band** over
> postcard-rpc (`SelectProbeEndpoint` / `AttachRequest`). So there is **no
> CLI injection point** for the agent; the earlier "agent injects `--probe`"
> model is dropped.

Decided agent model (per #1710):

- **Byte-proxy `probe-rs serve`, one server per board.** The agent spawns a
  `probe-rs serve` per board over a **Unix socket** (loopback, no TLS/WS/auth
  needed on that hop), each locked to its physical probe via a per-user
  `ProbeAccess::Allow([serial])` + per-board token. The agent byte-splices the
  raw `u32-LE length-prefixed postcard` stream through the relay — **zero
  probe-rs parsing**. Per-board (reused across a holder's many invocations),
  recycled on release for cleanup. This matches time-based sharing (§6).
- **Isolation comes from us, not from `serve` flags.** `ProbeAccess` per-board
  is the defense-in-depth fence so a leaseholder can only touch its own board,
  in addition to the fleet lease layer.
- **Embedding probe-rs as a library is unnecessary for v1** — the subprocess
  `serve` model is byte-compatible with any deployed probe-rs version.
- **`probe-rs gdb` / `debug` are NOT remote-capable in 0.31; gdb is tunneled as
  a second opaque channel.** gdb runs a separate local TCP stub (default
  `127.0.0.1:1337`), not over postcard-rpc. So the fleet runs `probe-rs gdb`
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
  tunnel) is an optional follow-up.

Agent also owns **USB power** behind a `PowerControl` trait: `uhubctl` (per-hub
port), GPIO relay, or `none`. Used for post-lease cleanup and fault recovery,
and exposed explicitly via `ctl`.

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

## 5. The dial-out connection (NAT traversal)

The agent opens **one persistent mTLS connection out** to the coordinator and
holds it. All coordinator→agent commands travel back down that same connection,
so the Pis need **no inbound ports**. Over this connection:

- agent → coordinator: register, report inventory, heartbeat, emit
  faults/logs/power events.
- coordinator → agent: "open a probe-rs session to board X for lease L",
  "power-cycle board X", "kill session", "what's your state".
- a **leased opaque channel** carries the data plane (probe-rs postcard-rpc
  frames — flash bytes, RTT) multiplexed alongside the small control RPCs.

The server→client direction is the crux. How we get it depends on the §3
transport choice:

- **myelin (Option A):** `DuplexStreamTransport` — genuine call-and-serve both
  ways over one stream, `api_id` multiplexing for control traits + data channel.
- **postcard-rpc only (Option B, preferred):** coordinator→agent commands are
  modeled as `ToClient` Topics (or a reverse Endpoint channel); we multiplex the
  opaque data channel over the same TLS pipe ourselves.

Either way the agent-dials-out property and the opaque data plane are identical;
only the control-plane ergonomics differ.

## 6. Auth & leases

- **Connection auth:** mTLS client cert → principal (agent id, or user/service
  account).
- **Capability token:** coordinator issues a signed, short-TTL token scoped to
  `{lease_id, board_id, allowed_ops}`. The agent verifies the token's signature
  locally; it does not need to call back to the coordinator per operation.
- **Lease lifecycle:** `request{constraints, duration, priority}` →
  `Leased{board, agent, channel, token, expires}` or `Queued`. Heartbeat
  renews; missed heartbeats free the board and trigger agent cleanup.
- **Fairness v1:** FIFO queue + per-principal concurrency cap + priority classes
  (interactive dev > nightly CI > soak). Grow later.

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
- **`gdb` is special (not remote-capable in probe-rs 0.31).** It is *not*
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

The agent reconciles discovered probes against this file; unknown probes are
reported but not leasable until declared.

## 9. Crate layout (proposed)

```
probe-rs-fleet/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ fleet-proto/             # service traits (postcard-rpc/myelin) + shared wire types (no I/O)
│  ├─ fleet-core/              # Board/Lease/Policy domain + scheduler (pure, unit-testable)
│  ├─ fleet-tls/               # rustls config, cert pinning, TLS stream glue
│  ├─ fleet-agent/             # probe-rs process control, USB power, boards.toml
│  ├─ fleet-coordinator/       # sqlite state, scheduler, auth, relay
│  ├─ fleet-sidecar/           # probe-rs CLI shim + relay client
│  └─ fleet-bin/               # single multi-role binary; thin dispatch
└─ docs/
```

`fleet-core` stays pure so the scheduler is testable without sockets or USB.

## 10. Open questions / decisions to confirm

**Resolved since first draft:**

- *probe-rs transport* = postcard-rpc 0.12 (confirmed from source). Data plane
  tunnels opaque postcard-rpc frames (§3).
- *"time-based"* = time-based **sharing**: extendable board claims across many
  probe-rs invocations, not lease-per-run (§6).
- *myelin* is now **optional** — since the data plane is already postcard-rpc,
  reusing it for the control plane lets us drop myelin (§3 Option B, preferred).

**Still open:**

1. **Control-plane transport: drop myelin? (§3)** Preferred path is postcard-rpc
   for both planes (one stack, no myelin). Confirm before scaffolding, since it
   changes `fleet-proto`'s dependencies. If postcard-rpc's `ToClient` topics
   make coordinator→agent commands too awkward in practice, we keep myelin for
   control only. **Needs your call.**
2. **Does probe-rs's postcard-rpc server already expose remote probe/chip
   selection over the wire?** If yes, plain proxying is sufficient and the agent
   only manages process lifecycle + `--probe`. If not, file tasks against
   probe-rs (or myelin, per your offer). Needs a look at probe-rs's server impl.
3. **gdb / TCP tunneling.** *Resolved (v1):* `probe-rs gdb` is not
   remote-capable in 0.31, so the agent runs `probe-rs gdb` locally and its raw
   gdbremote TCP is tunneled as a **second relay channel** (`ChannelKind::Gdb`),
   parallel to the postcard-rpc data plane (see §4.2, §7). Both planes share the
   same opaque `DataFrame` byte-pump; the coordinator relays gdb frames
   identically and a lease may hold a data channel and a gdb channel
   concurrently. **Latency:** the splice sets `TCP_NODELAY` on both loopback
   hops and flushes each chunk immediately (no Nagle batching), so gdb traffic
   is not coalesced. gdb is request/response and tolerant of LAN-scale RTT; the
   two mTLS relay hops add ~2×RTT per round-trip, which is acceptable for
   interactive use. Revisit (e.g. a lower-overhead path) only if step-debugging
   feels sluggish on a real deployment. *Optional follow-up:* an upstream
   probe-rs feature request to make `gdb` drive a remote `Session` over
   postcard-rpc would let gdb ride the existing data plane and drop this bespoke
   tunnel.
4. **probe-rs process lifecycle.** Decided-ish: **one server process per board**,
   possibly per lease for isolation. Confirm per-lease vs per-board-reused.
5. **Sidecar install UX.** argv0 `probe-rs` shim on PATH vs explicit
   `fleet sidecar run -- …` wrapper. Which install story do you want?
6. **Buffer sizing.** Concurrent ops per connection + flash-chunk buffer size —
   measure against real ariel-os flash images. (Deferred to implementation.)
```
