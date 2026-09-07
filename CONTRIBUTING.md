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

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

Only the first of these is gated in CI today; the other two are what reviewers
expect to have been run.
