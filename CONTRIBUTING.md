# Contributing

## Formatting

The tree is **rustfmt-clean**, and CI enforces it
(`.github/workflows/fmt.yml` runs `cargo fmt --all --check` on every push and
pull request). Before pushing:

```sh
cargo fmt --all
```

There is no `rustfmt.toml`: the default style is the whole rule, so there is
nothing to argue about and nothing to configure.

### Formatting is whatever *current stable* rustfmt produces

The workflow pins no toolchain — it uses the runner's stable rustfmt — so the
style tracks stable rather than a frozen version. **If `cargo fmt --all --check`
fails on a tree you did not change, your rustfmt differs from CI's: run
`rustup update` first**, before hunting for a real formatting mistake.

The whole-tree pass was produced with:

```
rustfmt 1.9.0-stable (2d8144b788 2026-07-07)   # rustc 1.97.0
```

A future stable rustfmt may reflow a few lines differently; when it does, the
fix is one more `cargo fmt --all` commit, not a pin.


### Make `git blame` skip the reformat

The whole tree was reformatted in one commit
(`0eb5a004db0a5c25de890c0fe4802a75092af3c6`). Left alone, `git blame` credits
that commit for every rewrapped line. `.git-blame-ignore-revs` lists it; point
git at the file **once per clone**:

```sh
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

The setting lives in `.git/config`, which is not tracked, so a fresh clone
needs it again. GitHub's blame view reads `.git-blame-ignore-revs`
automatically and needs no configuration.

Add a revision to that file only when it is provably behaviour-preserving
(a bulk reformat or a mechanical rename), and always as the full 40-character
SHA — git rejects abbreviated ones.

**Verifying it works.** Once the config above is set, a bare `git blame`
*already* ignores the reformat, so comparing it against `--ignore-revs-file`
compares ignore-on with ignore-on and always shows zero difference — which
looks exactly like a broken ignore file. An empty file or `/dev/null` is no
control either: `--ignore-revs-file` *supplements* the configured file rather
than replacing it. Use `--no-ignore-revs-file` (or `-c blame.ignoreRevsFile=`)
as the control, and probe a file the reformat actually touched, e.g.
`crates/fleet-core/src/scheduler.rs` (14 lines credited to the reformat with
the ignore file, 392 with `--no-ignore-revs-file`) or
`crates/fleet-coordinator/src/core.rs`. Do not probe
`crates/fleet-proto/src/ids.rs:141` — the reformat never touched it, so it
blames the same commit either way and proves nothing.

About 45 lines tree-wide stay credited to the reformat even when it is working.
Those are tokens rustfmt newly emitted when splitting expressions (`)`, `],`,
`;`, `0,`); they have no earlier author to fall back to, so crediting the
reformat is correct. Expected residue, not a failure.

## The forgs dependency

Identity and auth come from [forgs](https://github.com/kaspar030/forgs), a
regular crates.io dependency (`forgs`, `forgs-store`, `forgs-http`,
`forgs-idp`, `forgs-client`, all at the same version in the root
`Cargo.toml`). A plain clone builds as-is; no sibling checkout is needed.

- **Bumping forgs:** change the `version` on all five entries, then
  `cargo build --workspace` to refresh `Cargo.lock`.
- **Co-developing forgs and fleet:** check forgs out next to this repo
  (`../forgs`) and uncomment the `[patch.crates-io]` block at the end of the
  root `Cargo.toml` (or put the same table in `.cargo/config.toml`). Do not
  commit it uncommented; publish the forgs change and bump the version instead.

## Publishing to crates.io

Nothing has been published yet. Open points before the first release:

- **Crate names.** `fleet-coordinator` is already taken on crates.io by an
  unrelated project; the other `fleet-*` names were free when checked
  (2026-10). The rename (e.g. `probe-rs-fleet-*`, with `fleet-bin` becoming
  `probe-rs-fleet`) is still to be decided.
- **Copyright holder** in `LICENSE-MIT` is to be confirmed.

Every crate's metadata is inherited from `[workspace.package]`; the packaged
files are an `include` allowlist per crate (sources, `LICENSE-*` — symlinks to
the repo root — and, for `fleet-coordinator`, `build.rs`, `migrations/` and
`web/`, which are embedded at compile time). Tests and fixtures are not shipped.

**Versions.** Internal crates are listed in `[workspace.dependencies]` with
both `path` and `version`; bump those `version`s together with
`workspace.package.version`.

**Order.** A crate can only be published once the workspace crates it depends
on (including dev-dependencies) are on crates.io:

1. `fleet-proto`
2. `fleet-core`
3. `fleet-tls`
4. `fleet-wire`
5. `fleet-agent`, then `fleet-sidecar` (dev-depends on `fleet-agent`)
6. `fleet-coordinator` (dev-depends on `fleet-agent` and `fleet-sidecar`)
7. `fleet-bin`

**Checking.** `cargo package --list -p <crate>` shows what would ship.
`cargo package -p fleet-proto -p fleet-core …` (several `-p` at once) verifies
crates that depend on unpublished siblings through a local overlay; a single
`cargo publish --dry-run -p <crate>` fails on registry resolution until its
workspace dependencies are actually published. Recent cargo (1.90+) can do the
whole thing with `cargo publish --workspace`, which publishes in dependency
order.

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

CI gates formatting (`fmt.yml`) and builds the workspace plus runs the
`fleet-coordinator` and `fleet-bin` tests (`ci.yml`). Clippy and the full
`cargo test --workspace` are not gated; reviewers expect them to have been run.
