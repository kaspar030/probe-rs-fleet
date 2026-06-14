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
curl -sSLO https://github.com/probe-rs/probe-rs/archive/refs/tags/v0.31.0.tar.gz
tar xzf v0.31.0.tar.gz && cd probe-rs-0.31.0
rustup target add armv7-unknown-linux-musleabihf   # probe-rs pins a toolchain via rust-toolchain.toml
# same CC_/LINKER/RUSTFLAGS env as the TL;DR above
cargo build --release -p probe-rs-tools --bin probe-rs \
  --no-default-features --features remote \
  --target armv7-unknown-linux-musleabihf
```

`--features remote` enables `probe-rs serve` (the client/server mode the agent
proxies). The result is a static `probe-rs` that runs on the Pi.

## Pi-side runtime notes (Alpine)

- **USB probe permissions.** Alpine uses **mdev**, not udev, so probe-rs's udev
  guidance doesn't apply. For a quick unblock: `doas chmod 666
  /dev/bus/usb/<bus>/<dev>` for the probe. For a persistent rule, add an mdev
  rule matching the probe's `idVendor` (e.g. `1366` for SEGGER J-Link) granting
  group/world access. (A proper packaged install should ship this.)
- The agent needs `probe-rs` on its `PATH` (e.g. install to `/usr/local/bin`).
