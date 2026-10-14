# Cross-compiling the agent for Raspberry Pi

The fleet **agent** runs on Raspberry Pis. Many Pis are 32-bit ARMv7 (Pi 2,
older 3) and/or run musl-based distros (Alpine), for which **probe-rs ships no
prebuilt binary** (upstream releases cover only `x86_64`/`aarch64` **gnu**). So
both `probe-rs-fleet` and `probe-rs` itself must be cross-compiled.

Verified target: **Raspberry Pi 2 Model B, Alpine 3.23, `armv7l` / musl**, with
an nRF52840-DK (SEGGER J-Link) attached.
Triple: **`armv7-unknown-linux-musleabihf`**.

## TL;DR

```sh
rustup target add armv7-unknown-linux-musleabihf
# get a musl cross toolchain (provides the linker + a musl sysroot):
curl -sSLO https://musl.cc/armv7l-linux-musleabihf-cross.tgz
tar xzf armv7l-linux-musleabihf-cross.tgz
export PATH="$PWD/armv7l-linux-musleabihf-cross/bin:$PATH"

export CC_armv7_unknown_linux_musleabihf=armv7l-linux-musleabihf-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=armv7l-linux-musleabihf-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="-Ctarget-feature=+crt-static"

cargo build -p fleet-bin --release --target armv7-unknown-linux-musleabihf
```

Produces a **statically linked** `probe-rs-fleet`. Copy it (and a
cross-built `probe-rs`, below) to the Pi.

## Why `ring`, not `aws-lc-rs`

rustls defaults to the `aws-lc-rs` crypto provider, which vendors a **C**
crypto library (BoringSSL-derived). Cross-compiling that C to `*-musl` with a
**glibc** cross-gcc fails: it emits glibc time64 symbols (`open64`, `mmap64`,
`__nanosleep64`, …) that musl does not provide. The same applies to
`libsqlite3-sys` (the coordinator's bundled SQLite) and any other vendored C.

We avoid this entirely by using the **pure-Rust `ring`** provider: `rustls`,
`tokio-rustls`, and `rcgen` are configured with `default-features = false,
features = ["ring", …]`, and `fleet-tls` installs
`rustls::crypto::ring::default_provider()`. With `ring`, **any** Rust cross
toolchain builds the workspace — no clang, no sysroot CFLAGS dance. See commit
`adbe632`.

### Fallback: clang + aws-lc

If you must keep `aws-lc-rs`, **clang** *can* cross-compile its C (and SQLite's)
to armv7-musl, where glibc-gcc cannot — clang is a native cross-compiler. Point
it at the musl sysroot from the toolchain above:

```sh
SYSROOT="$PWD/armv7l-linux-musleabihf-cross/armv7l-linux-musleabihf"
export CC_armv7_unknown_linux_musleabihf=clang
export CFLAGS_armv7_unknown_linux_musleabihf="--target=armv7-unknown-linux-musleabihf --sysroot=$SYSROOT -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard"
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=armv7l-linux-musleabihf-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="-Ctarget-feature=+crt-static"
```

Both routes were verified to build and **run on the Pi**. We prefer `ring`
because it makes cross-compilation work with stock `rustup` + any linker, which
matters for a binary whose whole job is to run on diverse ARM Pis. The clang
route is documented only as an escape hatch.

## Cross-building `probe-rs serve` for the Pi

The agent spawns `probe-rs serve` locally, so the Pi also needs a `probe-rs`
binary. No upstream prebuilt exists for armv7-musl, so build it from source with
the **same** musl toolchain. probe-rs uses `nusb` (pure-Rust USB — no libusb C
dep); `hidapi` (C) is only pulled by the `cmsisdap_v1` feature, which we omit:

```sh
curl -sSLO https://github.com/probe-rs/probe-rs/archive/refs/tags/v0.32.0.tar.gz
tar xzf v0.32.0.tar.gz && cd probe-rs-0.32.0
rustup target add armv7-unknown-linux-musleabihf   # probe-rs pins a toolchain via rust-toolchain.toml (1.97.1 at v0.32.0)
# same CC_/LINKER/RUSTFLAGS env as the TL;DR above
cargo build --release -p probe-rs-tools --bin probe-rs \
  --no-default-features --features remote \
  --target armv7-unknown-linux-musleabihf
```

`--features remote` enables `probe-rs serve` (the client/server mode the agent
proxies). The result is a static `probe-rs` that runs on the Pi.

> The `remote` feature is still **opt-in** at v0.32.0 (`default = []`), so the
> flag above is required. Post-0.32 master flips `remote` on by default, at
> which point this flag becomes unnecessary — see issue #298.

## Pi-side runtime notes (Alpine)

- **USB probe permissions.** Alpine uses **mdev**, not udev, so probe-rs's udev
  guidance doesn't apply. For a quick unblock: `doas chmod 666
  /dev/bus/usb/<bus>/<dev>` for the probe. For a persistent rule, add an mdev
  rule matching the probe's `idVendor` (e.g. `1366` for SEGGER J-Link) granting
  group/world access. (A proper packaged install should ship this.)
- The agent needs `probe-rs` on its `PATH` (e.g. install to `/usr/local/bin`).

## The WebSocket stack (architecture revision 2)

Revision 2 moved the control plane from a bespoke length-prefixed TCP protocol
to **binary WebSocket messages over HTTPS** (§3.5), so it can sit behind an
ordinary reverse proxy. That drags a whole HTTP stack into a binary whose job is
to run on diverse ARM Pis, which is exactly the constraint that forced `ring`
over `aws-lc-rs` in the first place — so it was verified before any of the code
was written, and re-verified before hand-off.

**Result: a statically linked 32-bit ARM ELF with zero `aws-lc-rs`.**

Verified crates (all `default-features = false`, `ring` only):

| Crate | Role |
|---|---|
| `axum` 0.8 (`http1,tokio,ws,json`) | the coordinator's router + WS upgrade |
| `tokio-tungstenite` 0.29 (`connect,handshake,rustls-tls-webpki-roots`) | the dial-out client, via `fleet-wire` |
| `hyper` 1 + `hyper-util` (`client-legacy`, `server-auto`) | the HTTP client (`forgs-client`: login, refresh, API keys, `/node/*`); the TLS-terminating server loop |
| `hyper-rustls` 0.27 (`ring,tls12,webpki-tokio`) | HTTPS for that client |
| `tokio-rustls` / `rustls` 0.23 (`ring`) | TLS |
| `webpki-roots` | trust anchors, compiled in rather than read from the platform |
| `jsonwebtoken` 10 (`rust_crypto`) | the GitHub Actions OIDC verifier (§6.7), behind `forgs-idp`'s `oidc` feature — see below |

Reproduce it (this is the exact invocation, not a paraphrase):

```sh
export PATH="$HOME/toolchains/armv7l-linux-musleabihf-cross/bin:$PATH"
export CC_armv7_unknown_linux_musleabihf=armv7l-linux-musleabihf-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=armv7l-linux-musleabihf-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="-Ctarget-feature=+crt-static"

cargo build -p fleet-bin --release --target armv7-unknown-linux-musleabihf

file target/armv7-unknown-linux-musleabihf/release/probe-rs-fleet
#   ELF 32-bit LSB executable, ARM, EABI5 … statically linked

# The regression check that matters. Expect NO output:
cargo tree -p fleet-bin --target armv7-unknown-linux-musleabihf \
  --edges normal,build | grep -i aws-lc
```

(`ring`'s build script needs the cross-gcc on `PATH`, hence the toolchain — the
same requirement the baseline build already had.)

If `aws-lc-rs` ever reappears in that tree, something added a dependency without
`default-features = false`, or enabled a feature that flips rustls's default
provider. Find it with `cargo tree -i aws-lc-rs` and fix the feature flags
rather than reaching for the clang escape hatch below.

### Keep two versions of tungstenite off the Pi

`axum` depends on `tokio-tungstenite` internally, and `fleet-wire` depends on it
directly for the dial-out client. `fleet-bin` links both the coordinator and the
agent, so a version mismatch ships **two** copies of tungstenite (and its
`sha1`/`rand`/`data-encoding` tail) on every node. The workspace therefore pins
`tokio-tungstenite` to the major `axum` uses; bump the two together and re-run:

```sh
cargo tree -p fleet-bin --target armv7-unknown-linux-musleabihf --edges normal \
  | grep -oE 'tungstenite v[0-9.]+' | sort -u    # expect exactly one line
```

### Layering: no HTTP *server* framework in the agent

`axum`'s adapter for the wire traits lives in `fleet-coordinator`
(`src/ws_axum.rs`), not in `fleet-wire`, so `fleet-agent` and `fleet-sidecar`
link only the client half. `crates/fleet-agent/tests/no_http_server_dep.rs`
enforces this.

**The same test fences identity.** Since the forgs switch there is no
`fleet-auth` crate; identity lives in the forgs workspace
([github.com/kaspar030/forgs](https://github.com/kaspar030/forgs), a pinned
git dependency), and its crates are split exactly along this line:

| crate | linked by | what it pulls |
|---|---|---|
| `forgs` (pure core, no IO) | `fleet-coordinator`, `fleet-bin` | serde, sha2, ulid |
| `forgs-store` | `fleet-coordinator` only | sqlx (SQLite) |
| `forgs-http` | `fleet-coordinator` only | axum |
| `forgs-idp` (`client`, `oidc`) | `fleet-coordinator` only | hyper client, `jsonwebtoken` |
| `forgs-client` | `fleet-bin` only (CLI login, keys, `/node/*` calls) | hyper client + rustls/ring; **no** axum, no sqlx |

`fleet-agent`, `fleet-sidecar`, `fleet-proto`, `fleet-core` and `fleet-wire`
link **no forgs crate at all**: they only ever *present* a bearer token and
stay prefix-agnostic, and fleet-proto carries its own serde mirror of the
subject key. The test forbids `axum`, `hyper`, `forgs-store`, `forgs-http` and
`sqlx` in `fleet-agent`'s graph, and `forgs-http`, `forgs-store`, `axum` and
`sqlx` in `fleet-sidecar`'s. forgs keeps the same pure-Rust, `ring`,
`default-features = false` discipline as this workspace, so none of it changes
the musl build; the `aws-lc` check above covers it.

To be accurate about what that buys: it is **not** what keeps the Pi build
working — `fleet-bin` links the coordinator, so axum ships on the Pi regardless.
It is a layering rule. A library that discovers probes and dials outward should
not need a server framework to compile, and the moment `fleet-agent` can reach
for `axum::extract::ws::WebSocket` the `WireTx`/`WireRx` seam stops being load
bearing and the next transport change has to be made twice.

### The OIDC verifier's crypto tail (and what the feature gate actually buys)

Architecture §6.7 added GitHub Actions workload-identity verification, which
means **`jsonwebtoken`** and its signature-algorithm tail: `rsa`,
`num-bigint-dig`, `p256`, `p384`, `ed25519-dalek`. It sits behind `forgs-idp`'s
off-by-default `oidc` feature, enabled by exactly one crate — `fleet-coordinator`,
the only one that verifies a token.

Be accurate about what that gate buys, because the obvious reading is wrong:

- **It does not keep the tail off the Pi.** `fleet-bin` links the coordinator,
  so `jsonwebtoken` is in the shipped binary's graph on every target, exactly as
  `axum` is. `cargo tree -p fleet-bin --target armv7-unknown-linux-musleabihf -i
  jsonwebtoken` prints it.
- **What it does buy** is that `fleet-agent` and `fleet-sidecar` link none of it
  — the same layering rule as the section above, for the same reason. A library
  that discovers probes has no business compiling an RSA implementation, and a
  crate that only ever *presents* a bearer token should not gain the ability to
  verify a JWT by accident.
- **The cross-compile is unaffected**, which is the claim that matters here. The
  whole tail is pure Rust: it pulls no `cc`/`bindgen` build script, needs no
  sysroot CFLAGS, and does not touch rustls's provider selection. The
  `aws-lc-rs` regression check above stays empty, and
  `--features rust_crypto` (not `aws_lc_rs`) on the workspace's `jsonwebtoken`
  pin is what keeps it that way. Flipping that feature would put a vendored C
  crypto library back in the graph and break the musl build in the way this
  document opens by describing.

