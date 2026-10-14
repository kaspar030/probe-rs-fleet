# CI on GitHub Actions: hardware, no secrets

A GitHub Actions job can flash and test a real board in the lab **without a
single stored credential**. The job asks GitHub for a signed OIDC token, the
coordinator verifies it against GitHub's published keys, and the job gets a
fleet token that lives as long as the job does.

Two halves, and they belong to two different people:

- the **fleet admin**, who owns the hardware, runs one `grant` and configures
  one TOML block (below);
- the **repo maintainer**, who owns the workflow, adds `permissions: id-token:
  write` and two lines of YAML.

Nothing is copy-pasted between them except the coordinator's URL. See
`docs/architecture.md` §6.7 for why it is shaped this way; this file is how to
use it.

If your runner is not GitHub Actions — a self-hosted Jenkins box, say — skip to
[the auth-key fallback](#the-auth-key-fallback-for-runners-with-no-workload-identity),
and read the paragraph that says it is the weaker path.

---

## The fleet admin's side

### 1. Configure the issuer

Add a `[github_actions]` block to `coordinator.toml`. The fully-commented
reference is `examples/coordinator.toml`; the minimum is:

```toml
[github_actions]
audience = "https://fleet.example"   # this coordinator's public_url
```

**`audience` has no default and the coordinator refuses the block without one.**
GitHub's own default audience is `https://github.com/<owner>`, which is not
specific to any service: a token minted for some *other* system under the same
owner, which also took the default, would otherwise be replayable against your
fleet. Set it to the coordinator's `public_url` and have the workflow ask for
that audience explicitly. Everything else (`issuer`, `jwks_url`,
`jwks_refresh_secs`, `jwks_min_refetch_secs`, `workload_token_ttl_secs`) has a
working default.

Omitting the block entirely is a supported deployment. `POST /auth/token` then
answers `503 workload_unconfigured`, and `ci login` turns that into a
sentence naming the missing block.

The block is independent of the login providers (`[[auth.providers]]`): a fleet
may have CI without browser login, or the reverse.

### 2. Grant the repository

```sh
probe-rs-fleet grant --org acme --repo ariel-os/ariel-os \
    --select 'tag=nrf52' \
    --ops flash \
    --ttl 30d
```

The grant is issued by the org you act in (`--org`, a name or id; default your
personal org) and covers only that org's boards. `--repo` conflicts with the
positional grantee; exactly one of the two is required. The grantee syntax is
the same everywhere (`grant`, `POST /api/v1/grants`):

| grantee | resolves to |
|---|---|
| `--repo owner/name`, or `repo:owner/name` | `gha/workload:owner/name` (lowercased) — a CI repository |
| a username, e.g. `bob` | `user:<ULID>`, looked up **once** at grant time, so the grant survives a rename and never follows a reused name |
| a subject key, e.g. `<org id>/workload:agent:builder`, `<org id>/node:…`, `user:01J…` | itself |

Usernames are fleet usernames (chosen at first login), **not** GitHub logins;
an unknown one is `no such user`. Validation stays server-side, so a client
cannot talk the coordinator into a subject key it would not build itself. The
command prints the resolved subject key (`gha/workload:ariel-os/ariel-os`) and
a one-line reminder that the **owner** is not granted.

That reminder is the whole trust rule, and it is worth reading twice:

> **A grant names one repository. Its owner is not granted.** A fork, or a new
> repo under the same owner, is a different subject and gets nothing.

`repository_owner` *is* verified as a claim and recorded in the audit trail — it
is simply never consulted for access. This is deliberate: the alternative is
that anyone who can create a repo under your GitHub org, or fork yours, inherits
your lab hardware.

Creating a grant needs `admin` in the org (in a personal org, that is you).
Grants must expire (at most 365 days); `--ttl` defaults to 30 days. `grant list` shows them,
`grant revoke <id-prefix>` withdraws one — and revocation is real: leases the
grantee holds on boards it may no longer reach are released and their relay
channels torn down, rather than left running until the TTL expires.

### 3. What you will see when it works

Each exchange writes a `workload.token.mint` row to the identity audit
(`forgs_audit`), and the workload token row records the verified claims (repo,
owner, ref, workflow, run id). Plus the
ordinary `lease.grant` / `lease.release` rows in the granting org's audit log, whose `holder` is
`gha/workload:owner/repo`. `leases` rows are never deleted, so "which repo held
which board, for how long" is answerable after the fact. No billing is built.

---

## The repo maintainer's side

Copy `examples/github-actions.yml`. The essentials:

```yaml
permissions:
  contents: read
  id-token: write          # without this there is no OIDC token at all

steps:
  - run: |
      probe-rs-fleet ci login \
        --fleet-url https://fleet.example \
        --audience  https://fleet.example
  - run: probe-rs run --chip nRF52840_xxAA target/…/my-test
    env:
      PROBE_RS_FLEET_SELECT: nrf52
```

### No secrets

There is no `secrets.` reference anywhere in that workflow, and that is the
point. `ci login` reads `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which the runner injects **only** when the job
declares `permissions: id-token: write` and which are scoped to that one job. It
spends them once, on GitHub's own token service, and writes them nowhere.

Forgetting `id-token: write` is by far the most common failure; `ci login` says
so by name rather than reporting a generic error.

### The audience must match

`--audience` must equal the coordinator's configured `audience`. It defaults to
`--fleet-url`, which is the right value in any ordinary deployment (where the
coordinator's `audience` is its own `public_url`). A mismatch is a
`401 invalid_grant` with no further explanation — see
[failure shapes](#what-the-errors-mean).

### Where the token goes

`ci login` appends `PROBE_RS_FLEET_COORDINATOR`, `PROBE_RS_FLEET_TOKEN` and
`PROBE_RS_FLEET` to `$GITHUB_ENV` when it is set, so later steps in the same job
see them. **It never prints the token to stdout on that path** — stdout is the
job log, and a credential in a log is a credential in whatever archives that
log. Off GitHub Actions (no `$GITHUB_ENV`) it prints `export …` lines for
`eval "$(…)"` instead.

It writes **nothing** to the fleet file. A CI runner's credential comes from the
environment and lives for one job; the sidecar reads exactly those variables
(`crates/fleet-sidecar/src/selector.rs`), so nothing else has to know.

### The job must be shorter than the token

`workload_token_ttl_secs` defaults to **1 hour** (12h ceiling), and there is **no
refresh path for a workload token** — refresh is session-only. A job that runs
past the expiry must re-run `ci login`; put it before the long step, or split the
job. `ci login` prints the expiry and says this in one line, so it is not
something to discover as a flake at 3am.

### A wide matrix contends — and a contended leg now *waits*

Read this before widening a matrix; the intuitive reading is wrong in a
different way than it used to be.

`max_concurrent_per_subject` (default 2) is keyed by the **subject**, and every
job in the repo authenticates as the *same* subject (`gha/workload:owner/repo`)
— so the cap is effectively **per repo**, not per job, per matrix leg or per
workflow. Ten legs against a two-board pool are ten requests from one subject.

The coordinator now answers three different situations differently, and only
one of them is a wait:

- **every matching board is busy** — the request is queued, and `probe-rs run`
  **waits** for its turn, up to `PROBE_RS_FLEET_QUEUE_WAIT` (default 300s). If a
  leg ahead of it finishes inside that window, the coordinator pushes the grant
  down the same connection and the leg proceeds as if it had never queued. Only
  when the wait expires does the step fail:

  ```
  coordinator declined: still queued at position 1 after 300s; giving up
  ```

- **the selector matches nothing you can reach** — no amount of waiting helps,
  so it fails immediately and says how much fleet you can actually see;
- **you are at the cap** — likewise immediate, and it names the knob rather than
  blaming contention.

So the practical rules are:

- **`max-parallel` is a throughput knob, not a correctness requirement.** Bounding
  a matrix to `max_concurrent_per_subject` still avoids paying the queue wait on
  every leg, and is worth doing for a long matrix. It is no longer the thing
  standing between you and spurious failures.
- **Size the wait to the job, not to the fleet.** A leg whose flash-and-test
  cycle is two minutes wants a wait comfortably longer than the legs ahead of
  it; a smoke test that should never queue can set
  `PROBE_RS_FLEET_QUEUE_WAIT=0` and fail fast, which is exactly the old
  behaviour.
- **An abandoned leg leaves nothing behind.** When a leg gives up (or is
  cancelled, or the runner dies), its connection closes and the coordinator
  drops its queued request — so it can never later be promoted onto a board
  nobody is listening for. A lease it was actually *holding* still survives to
  its TTL, deliberately: that is what lets a sidecar reconnect.

`ctl lease` behaves differently on purpose: it prints `queued at position N` and
exits **zero** without waiting, because an operator wants to know the state of
the queue rather than to be parked in it. Note that its slip lasts only while
the command runs — `ctl` opens one connection per command, and the same
drop-on-disconnect rule applies.

One thing you never have to plan for: **a CI lease is clamped to CI priority**
whatever it asks for, so a CI run can never outbid a developer sitting at a
desk. That is §6.6's fairness ordering (interactive dev > nightly CI > soak)
being enforced rather than trusted.

### Exit codes still mean what they mean

The sidecar runs the **genuine** `probe-rs` client against the leased board and
propagates its exit status, so `probe-rs run`'s exit code is still the
embedded-test pass/fail signal (architecture §7). Nothing about the CI path
changes that: the fleet relays bytes, it does not interpret them.

---

## What the errors mean

| what you see | what happened | what to do |
|---|---|---|
| `coordinator declined: still queued at position N after 300s; giving up` | every board matching your selector was busy for the whole wait | raise `PROBE_RS_FLEET_QUEUE_WAIT`, narrow the matrix (`max-parallel`) so fewer legs compete, or ask for a bigger pool. Nothing is left queued behind the failure |
| `coordinator declined: no board matches \`<selector>\`; ctl list shows N boards you can reach` | the selector matches nothing you have access to — a typo, or a grant you do not have | run `ctl list` and select from what it shows. Waiting cannot fix this, which is why it fails immediately |
| `coordinator declined: you already hold N leases (cap max_concurrent_per_subject = N); release one or raise the cap` | your **repo** is at its concurrency cap; the fleet may well be idle | bound the matrix with `max-parallel`, release a lease, or ask the fleet admin to raise the cap for your subject |
| `401 invalid_grant` | the coordinator refused the credential and will not say why — a bad token, **or a valid token for a repo with no grant** | check that the fleet admin ran `grant --repo <owner>/<name> …` (being under a granted owner is deliberately not enough), then `--audience` against the coordinator's configured one, then the runner's clock; the real reason is in the **coordinator's** audit log |
| `503 workload_unconfigured` | that coordinator has no `[github_actions]` block | the operator adds one, or use `ci login --auth-key` |
| `ACTIONS_ID_TOKEN_REQUEST_URL is not set` | the job has no workload identity | add `permissions: id-token: write` to the job |

The flat `401` is deliberate. Expiry, wrong audience, wrong issuer, bad
signature, a missing claim, an unknown key id — and a verified token for a
repo with no live grant — all answer identically, so the
endpoint is not an oracle. The reason is recorded coordinator-side with a
stable label (`oidc.reject.*`, `workload.reject.no_grant`).

### Telling "fork denied" apart from everything else

A fork of a granted repo, or a new repo under a granted owner, gets the flat
`401`. The audit log names it exactly: a `workload.reject.no_grant` row whose
subject is the repo's workload key and whose detail is
`repository=acme/firmware-fork owner=acme`.

The owner is logged beside the repo so the "but I granted the org!" case is one
line to diagnose. The fix is a grant for that repo, if you actually want the
fork to have your hardware.

---

## The auth-key fallback, for runners with no workload identity

A self-hosted Jenkins box cannot mint a GitHub workload identity, so there is a
fallback. **It is the weak path, and it is worth being blunt about why:** it is
a long-lived bearer secret sitting in somebody else's CI configuration, usable
by anyone who can read that configuration or a log that leaked it. The OIDC path
above stores no secret anywhere at all. Prefer it whenever the runner can mint
an identity.

Mint the key (any org member can, over the API, with the login they already
have). It is a forgs API key of purpose `ci`, belonging to the org you name:

```sh
probe-rs-fleet auth-key create --org acme --purpose ci \
    --tag nrf52 \
    --ops flash,attach \
    --ttl 7d
```

Then, on the runner:

```sh
probe-rs-fleet ci login --fleet-url https://fleet.example --auth-key prfk1_…
```

Read the key from the CI system's secret store, not from a literal on the
command line: argv is visible to every process on the box.

What bounds the damage, and nothing else does:

- **org scope** — a key belongs to one org (`--org`, default your personal
  org), which must be one you are a member of: it can never exceed your own
  access, and its grant covers only that org's boards.
- **the selector** — the key's `--tag`s become the selector of the grant its
  redemption synthesises. A `ci` key with **no tags is refused**, at the mint and
  again at redemption, because an empty tag set is an empty selector and would
  match every board in the org.
- **ops** — `--ops` defaults to `flash,attach,reset,erase`. `power-cycle` is
  deliberately not in that default: an unattended runner cutting power to a lab
  board should be an explicit choice.
- **expiry** — API-minted keys must expire (30 day cap). The synthesised grant
  inherits the key's expiry, or gets a bounded 30-day one if the key never
  expires.
- **revocability** — `auth-key revoke <prefix>` deletes the key *and* cascades
  through the grant its redemption created, so live leases are torn down rather
  than left running to their TTL. This is why the mint output tells you the key
  carries a grant: revoking it takes down more than the credential, and that is
  intended.

Mechanically, redeeming a `ci` key does not widen anything: it upserts an
**ordinary grant** (a forgs grant row; the key's tags and ops, stored as its
payload, become the grant's selector and ops) — evaluated by the same
code as a `grant --repo` row and revocable by the same verb — to an org-scoped subject
`<org>/workload:key:<hash8>`, and then mints an ordinary workload token. Every
runner redeeming the same key is the same subject, so they share one grant row
(its id is derived deterministically from org and subject) and one concurrency budget.

That grant shows up in `grant list` like any other, and
`probe-rs-fleet grant revoke <id prefix>` withdraws it — leaving the key itself
valid, so the next runner to redeem it simply recreates the grant. To retire the
runner's access for good, revoke the **key**: that takes the credential and the
grant together.

A `node` key cannot be redeemed this way, and a `ci` key cannot enroll a node:
the purpose is checked before the key is consumed, so a mis-aimed single-use
key is not burned. That separation is the entire reason `purpose` exists.

### A named identity, so rotating the key does not fork the agent

Everything above derives the runner's identity from the **credential**: the
subject is `key:<hash8>`, and the grant id is derived from it. So rotating the
key — mint a new one, deploy it, retire the old — gives you a *new subject and a
new grant row*. The audit trail forks, the concurrency budget resets, and the
old grant lingers until it expires. For a long-running agent, that is the wrong
shape.

Give it a name instead:

```sh
probe-rs-fleet auth-key create --purpose agent --as builder \
    --tag nrf52 \
    --ops flash,attach \
    --ttl 30d
```

(`--purpose agent` is a spelling of `--purpose ci` — same credential, same code
path, better vocabulary for a key that is not per job. Listings show `ci`.)

That key redeems as `<org>/workload:agent:builder`, and its grant id is derived
from `(org, <org>/workload:agent:builder)` rather than from the hash. The rotation then looks like this,
and the identity never moves:

```sh
# 1. Mint the replacement with the SAME --as.
probe-rs-fleet auth-key create --purpose agent --as builder \
    --tag nrf52 --ops flash,attach --ttl 30d

# 2. Deploy the new secret to the runner and restart it.

# 3. Retire the old key, once nothing is using it.
probe-rs-fleet auth-key list          # find its hash prefix; check the IDENTITY column
probe-rs-fleet auth-key revoke <prefix>
```

Step 1's redemption re-upserts the *same grant row*: same id, same subject, same
audit history, same concurrency budget. `auth-key list` shows an `IDENTITY`
column so you can see which keys carry the name.

The name is lowercased and restricted to `[a-z0-9._-]`, starting with a letter
or digit, at most 64 characters — so you can retype it months later and get the
same identity, and so a name can never be mistaken for the `key:<hash>` form or
for a `gha/workload:owner/repo` repo subject. It is scoped to your org: two orgs
may each have a `builder`.

**The trade, and it is the important paragraph on this page.** Two live keys
sharing an `--as` are **one identity, and the grant belongs to the identity, not
to the key**. So step 3 above is not a no-op on the identity and it is not a
clean revocation either:

- revoking one key tears down the **shared** grant, and with it every live lease
  held under the name — including the *other* key's runner, mid-job;
- it does not end the identity: the surviving key re-creates the grant on its
  next redemption;
- and workload tokens already minted stay valid for the rest of their TTL (up to
  an hour; there is no refresh), so such a token regains access the instant any
  surviving key redeems.

Revoking one key of a shared identity is therefore a **disruption, not a
revocation**. Do step 3 when the old runner is idle. To retire the agent for
good: revoke *every* key carrying the name, then `probe-rs-fleet grant revoke
<id from grant list>`. Tokens already issued expire on their own within the hour.

### A persistent session, so the sandbox stops re-running `ci login`

The name above gives a long-running machine a persistent *identity*. It does not
give it a persistent *session*: the token `ci login` mints lives about an hour
and there is no refresh for it, so a sandbox has to re-run the command — which
is how people end up with an hourly cron job, or an `eval "$(probe-rs-fleet ci
login …)"` wrapper around every invocation that does not even propagate between
concurrent processes on the same box.

If that machine is a **sandbox you own** rather than a shared runner, hand the
key over once instead:

```sh
probe-rs-fleet agent login --fleet-url https://fleet.example \
    --auth-key "$PROBE_RS_FLEET_AUTH_KEY" --as builder
```

That stores the key in `~/.config/probe-rs-fleet/fleets/<name>.toml` (0600), and
`ctl` and the `probe-rs` shim re-redeem it as the session nears expiry — no cron
job, no wrapper, and concurrent processes on the machine share the renewed token
through that file.

Two conditions, both deliberate:

- **The key must be `--multi-use`.** A single-use key breaks on the second
  *process*, not merely the second hour. `agent login` refuses one, and detects
  it by redeeming twice — which spends a single-use key's one redemption, so it
  tells you the key is now gone.
- **The durable key is on disk.** That is the trade, and it is why `ci login`
  still writes nothing: a shared runner has no owner who can make it. Use this
  only where you are content to let the machine hold a persistent identity in
  its filesystem reach.

Architecture §6.7 has the mechanism, including why re-redemption is not the
refresh path that section says does not exist.

---

## What is not built

**No per-ref or per-workflow conditions.** A grant to `owner/repo` is a grant to
every branch and every workflow of that repo. The `ref`, `workflow`,
`job_workflow_ref` and `run_id` claims are captured on the token row and in the
audit detail, but nothing evaluates them. If you need "only `refs/heads/main`
may touch the lab", that is a filed follow-up, not something this version does —
capturing the claims now is what makes adding it a pure code change.
