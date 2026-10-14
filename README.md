# probe-rs-fleet

probe-rs-fleet shares embedded debug probes and the boards attached to them
across a team and its CI. Boards stay plugged into lab machines or Raspberry
Pis; a central coordinator knows which boards exist, who may use them, and who
holds one right now. A developer runs `probe-rs` as usual, and the fleet
transparently leases a matching remote board, relays the session to it, and
releases it afterwards. Build recipes such as laze need no changes.

Everything ships as one binary, `probe-rs-fleet`, with the role chosen by
subcommand. The coordinator schedules leases, relays probe traffic, and serves
a web UI; it runs behind an HTTPS reverse proxy. A node runs next to the
probes, dials out to the coordinator over WebSocket (no inbound ports), and
runs `probe-rs serve` for each leased board. The CLI covers login, sharing,
grants and leasing, and a sidecar shim (the same binary invoked as `probe-rs`)
forwards real probe-rs invocations through the fleet. Identity, login
sessions, orgs and API keys are provided by
[forgs](https://github.com/kaspar030/forgs), so users log in with GitHub,
Codeberg, GitLab or any OIDC provider.

## Quickstart

```sh
# On the coordinator host (configure a login provider in coordinator.toml first):
probe-rs-fleet coordinator init --public-url https://fleet.example
probe-rs-fleet coordinator

# On a machine with probes attached:
probe-rs-fleet login --fleet-url https://fleet.example
probe-rs-fleet node up

# On any logged-in machine:
probe-rs-fleet ctl list
probe-rs-fleet ctl lease id=<board>
```

`examples/coordinator.toml` documents the login provider setup and every
other coordinator key. `node up` registers the machine with your login and
then runs it; headless lab nodes can instead be approved from another machine
(`node approve`) or enrolled with an auth key (`auth-key create`). Linking the
binary as `probe-rs` on your `PATH` makes plain `probe-rs` commands use the
fleet.

## Documentation

- [docs/architecture.md](docs/architecture.md): design, transport, identity and authorization
- [docs/cross-compiling.md](docs/cross-compiling.md): building the node for Raspberry Pi
- [docs/ci-github-actions.md](docs/ci-github-actions.md): using fleet boards from GitHub Actions
- [docs/web-ui.md](docs/web-ui.md): the coordinator web UI and its API
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing and formatting

## License

Licensed under either of MIT or Apache-2.0, at your option.
