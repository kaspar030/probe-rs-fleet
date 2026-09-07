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

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

Only the first of these is gated in CI today; the other two are what reviewers
expect to have been run.
